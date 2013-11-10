(ns pocheshiro.core-test
  (:import [org.apache.shiro SecurityUtils]
           [org.apache.shiro.util ThreadContext ByteSource ByteSource$Util]
           [org.apache.shiro.mgt DefaultSecurityManager]
           [org.apache.shiro.web.mgt DefaultWebSecurityManager]
           [org.apache.shiro.authc AuthenticationException
            UsernamePasswordToken AuthenticationToken]
           [org.apache.shiro.authc.credential AllowAllCredentialsMatcher
            CredentialsMatcher]
           [org.apache.shiro.authz.permission DomainPermission]
           [org.apache.shiro.subject SimplePrincipalCollection])
  (:require [pocheshiro.core :as s]
            [compojure.core :as c]
            [clojure.test :refer :all]))

(use-fixtures :each
              (fn [f]
                (try (f)
                     (finally
                       (do (SecurityUtils/setSecurityManager nil)
                           (ThreadContext/remove))))))

(deftype MyToken []
  AuthenticationToken
  (getPrincipal [this] nil)
  (getCredentials [this] nil))

(def username "username")

(def valid-uptoken (UsernamePasswordToken. username "secret"))
(def wrong-uptoken (UsernamePasswordToken. "bad" "wrong"))

(defn pcs [principal realm-name]
  (SimplePrincipalCollection. principal realm-name))

(defn pass-matcher [password]
  (proxy [CredentialsMatcher] []
    (doCredentialsMatch [token info]
      (= password (.getCredentials info)))))

(defn verify-can-login-with [realm token]
  (SecurityUtils/setSecurityManager (DefaultSecurityManager. [realm]))
  (s/login! token)
  (is (.isAuthenticated (s/get-bound-subject)))
  (s/logout!)
  (SecurityUtils/setSecurityManager nil)
  (ThreadContext/remove))

(defn verify-cannot-login-with [realm token]
  (SecurityUtils/setSecurityManager (DefaultSecurityManager. [realm]))
  (try (s/login! token)
       (is false (str "Should fail for token: " token))
       (catch AuthenticationException e)
       (finally (SecurityUtils/setSecurityManager nil)
                (ThreadContext/remove))))

(deftest username-password-realm-test
  (testing "Hashes passwords with salt with a SHA hash and many iterations"
    (let [passwords (s/iterated-hashed-passwords {:hash-algo "SHA-256"
                                                  :hash-iterations 500000})
          plaintext "very-secret"
          our-encrypted-plaintext (.encryptPassword passwords plaintext)

          ; Realm with default params
          realm (s/username-password-realm
                  :get-authentication
                  (fn [token] (when (= username (.getPrincipal token))
                                {:principal username
                                 :credentials our-encrypted-plaintext})))]

      (verify-can-login-with realm (UsernamePasswordToken. username plaintext))
      (verify-cannot-login-with realm (UsernamePasswordToken. username "bad")))))

(deftest hashing-and-bcrypting-test
  (testing "Hashes passwords with salt with a SHA hash and many iterations"
    (let [passwords (s/iterated-hashed-passwords {:hash-algo "SHA-512"
                                                  :hash-iterations 12321})
          plaintext "very-secret"
          encrypted-plaintext (.encryptPassword passwords plaintext)]

      (is (re-seq #"SHA-512" encrypted-plaintext))
      (is (re-seq #"12321" encrypted-plaintext))))

  (testing "Bcrypts passwords"
    (let [passwords (s/bcrypt-passwords {:work-factor 5})
          plaintext "very-secret"
          encrypted-plaintext (.encryptPassword passwords plaintext)]

      (is (.passwordsMatch passwords plaintext encrypted-plaintext))
      (is (not (.passwordsMatch passwords "bad-pass" encrypted-plaintext))))))

(deftest defrealm-test
  (testing "Defines a realm overriding all of the parameters"
    (let [realm (s/defrealm-fn "test" (pass-matcher "passwordy-password")
                  :supports? (partial instance? UsernamePasswordToken)
                  :get-authentication
                  (fn [token] (when (= username (.getPrincipal token))
                                {:principal {:username username}
                                 :credentials "passwordy-password"
                                 :salt "salty-salt"}))
                  :get-authorization
                  (fn [pcs] (when (= (:username (.getPrimaryPrincipal pcs)) username)
                              {:roles [:manager]
                               :permissions ["raise-wage"
                                             (DomainPermission. "lower-wage")]})))]

      (let [auth-info (.getAuthenticationInfo realm valid-uptoken)]
        (is (= (-> auth-info .getPrincipals .getPrimaryPrincipal) {:username username}))
        (is (= (.getCredentials auth-info) "passwordy-password"))
        (is (= (.getCredentialsSalt auth-info) (ByteSource$Util/bytes "salty-salt"))))
      (is (not (.getAuthenticationInfo realm wrong-uptoken)))

      (let [auth-info (.getAuthorizationInfo realm (pcs {:username username} "test"))]
        (is (= (.getRoles auth-info) #{"manager"}))
        (is (= (.getObjectPermissions auth-info) #{(DomainPermission. "lower-wage")}))
        (is (= (.getStringPermissions auth-info) #{"raise-wage"})))
      (is (not (.getAuthorizationInfo realm (pcs "wrong" "test"))))

      (is (.supports realm valid-uptoken))
      (is (.supports realm wrong-uptoken))
      (is (not (.supports realm (MyToken.))))

      (verify-can-login-with realm valid-uptoken)
      (verify-cannot-login-with realm wrong-uptoken)))

  (testing "Defines a realm with default parameters"
    (let [realm (s/defrealm-fn "test" (pass-matcher "any")
                  :get-authentication (fn [token] nil))]

      (is (not (.getAuthenticationInfo realm valid-uptoken)))
      (is (not (.getAuthorizationInfo realm (pcs "any" "test"))))

      (is (.supports realm valid-uptoken))
      (is (.supports realm (MyToken.)))

      (verify-cannot-login-with realm valid-uptoken))))

(defn- test-realm [username]
  (s/defrealm-fn "testing" (AllowAllCredentialsMatcher.)
    :get-authentication
    (fn [t] (if (= username (.getPrincipal t))
              {:principal username}))
    :get-authorization
    (fn [pcs] {:roles [:developer]
               :permissions [:drop-tables]})))

(defn- servlet-session []
  (let [attributes (atom {})
        valid (atom true)]
    (proxy [javax.servlet.http.HttpSession] []
      (setAttribute [k v] (swap! attributes assoc k v))
      (getAttribute [k] (@attributes k))
      (removeAttribute [k] (swap! attributes dissoc k))
      (invalidate [] (reset! valid false)))))

(defn- servlet-request [req session]
  (proxy [javax.servlet.http.HttpServletRequest] []
    (getSession [create?] session)
    (getRemoteHost [] "localhost")
    (getAttribute [k] nil)
    (getCookies [] (into-array
                     javax.servlet.http.Cookie
                     (for [[cookie attrs] (:cookies req)]
                       (javax.servlet.http.Cookie. (name cookie) (:value attrs)))))
    (getContextPath [] "/")
    (getMethod [] (name (:request-method req)))
    (getQueryString [] "")
    (getRequestURI [] (:uri req))))

(defn- servlet-response [req resp-data]
  (proxy [javax.servlet.http.HttpServletResponse] []
    (addHeader [k v])
    (sendRedirect [to-uri] (swap! (:redirects resp-data)
                                  assoc (:uri req) to-uri))))

(defn- as-servlet-request [session request]
  (let [response-data {:redirects (atom {})}]
    (assoc request
           :servlet-request (servlet-request request session)
           :servlet-response (servlet-response request response-data)
           :response-data response-data)))

(defn- sec-manager [_]
  (DefaultWebSecurityManager. [(test-realm username)]))

(def ^:private sec-opts
  {:security-manager-retriever sec-manager})

(deftest middleware-test
  (let [request (as-servlet-request (servlet-session)
                                    {:uri "/test", :request-method :get})]

    (testing "Binds Shiro subject to the executing thread"
      (let [handler (fn [_] (s/get-bound-subject))]

        (testing "isn't bound by default"
          (is (thrown? org.apache.shiro.UnavailableSecurityManagerException
                       (handler request))))

        (testing "bound when wrapped into pocheshiro middleware"
          (is ((s/wrap-security handler sec-opts) request)))))

    (testing "Attaches principal to the request"
      (let [req-count (atom 0)
            handler (fn [r] (case @req-count
                              0 (do (s/login! valid-uptoken)
                                    (swap! req-count inc))
                              1 (:user r)))
            wrapped (s/wrap-security (s/wrap-principal handler) sec-opts)]

        (wrapped request)
        (is (= (wrapped request) username))))))

(deftest access-rule-test
  (let [access-count (atom {})
        accessed #(do (swap! access-count update-in [%] (fnil inc 0))
                      {:count (@access-count %)})
        is-first-time? #(not (@access-count %))
        session (servlet-session)
        request-to (fn [uri & more]
                     (as-servlet-request session
                       (apply merge {:uri uri, :request-method :get} more)))
        routes (c/routes
                 (c/GET "/no-control" []
                        (accessed "no-control"))
                 (c/GET "/redirect-fallback" []
                        (accessed "redirect-fallback"))
                 (c/GET "/login" request
                        (s/login! valid-uptoken)
                        (s/redirect-after-login! request "/redirect-fallback"))
                 (c/GET "/authenticated" []
                        (s/enforce s/authenticated
                          (accessed "authenticated")))
                 (c/GET "/custom-auth" []
                        (s/enforce (s/authorized (partial is-first-time? "custom-auth")
                                                 "First time only")
                          (accessed "custom-auth")))
                 (c/GET "/roles" []
                        (s/enforce (s/authorized {:roles #{:manager}})
                          (accessed "roles")))
                 (c/GET "/permissions" []
                        (s/enforce (s/authorized {:permissions #{:create-tables}})
                          (accessed "permissions")))
                 (c/GET "/both-roles-and-permissions" []
                        (s/enforce
                          (s/authorized {:roles #{:developer}
                                         :permissions #{:drop-tables}})
                          (accessed "both-roles-and-permissions")))
                 (c/GET "/or-rules" []
                        (s/enforce
                          (s/or* (s/authorized {:roles #{:developer}})
                                 (s/authorized {:roles #{:manager}}))
                          (accessed "or-rules")))
                 (c/GET "/and-rules" []
                        (s/enforce
                          (s/and* (s/authorized {:roles #{:developer}})
                                  (s/authorized (partial is-first-time? "and-rules")))
                          (accessed "and-rules"))))
        handler (s/wrap-security routes sec-opts)]

    (testing "Doesn't enforce security if not wrapped"
      (is (= 1 (:count (handler (request-to "/no-control"))))))

    (testing "Redirects to login-page"
      (let [request (request-to "/authenticated")]
        (handler request)
        (is (= (@(get-in request [:response-data :redirects]) "/authenticated")
               "//login")))) ;This is cleaned up by actual servlet response impl

    (testing "Redirects back to the requested page after authentication"
      (let [request (request-to "/login")]
        (handler request)
        (is (= (@(get-in request [:response-data :redirects]) "/login")
               "/authenticated?"))))

    (testing "Allows to access `authenticated` protected route"
      (is (= 1 (:count (handler (request-to "/authenticated"))))))

    (testing "Allows to access route with custom authorization check"
      (is (= 1 (:count (handler (request-to "/custom-auth")))))
      (let [failure (handler (request-to "/custom-auth"))]
        (is (= 403 (:status failure)))
        (is (= "First time only" (:body failure)))))

    (testing "Authorizes according to the roles"
      (is (= 403 (:status (handler (request-to "/roles"))))))

    (testing "Authorizes according to the permissions"
      (is (= 403 (:status (handler (request-to "/permissions"))))))

    (testing "Authorizes according to roles and permissions"
      (is (= 1 (:count (handler (request-to "/both-roles-and-permissions"))))))

    (testing "Requests either of authorization checks in an `or*` clause"
      (is (= 1 (:count (handler (request-to "/or-rules"))))))

    (testing "Requests both authorization checks in an `and*` clause"
      (is (= 1 (:count (handler (request-to "/and-rules")))))
      (is (= 403 (:status (handler (request-to "/and-rules"))))))))
