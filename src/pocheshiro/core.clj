(ns pocheshiro.core
  "Pocheshiro is a Clojure wrapper for the Apache Shiro security library
  tailored for use with Ring and Compojure.

  Pocheshiro must be run in a servlet container (sorry, no `http-kit`) because
  Apache Shiro depends on the servlet specification."
  (:import [org.apache.shiro SecurityUtils]
           [org.apache.shiro.realm AuthorizingRealm]
           [org.apache.shiro.authc UsernamePasswordToken
            SimpleAuthenticationInfo AuthenticationToken]
           [org.apache.shiro.authc.credential PasswordService PasswordMatcher
            DefaultPasswordService CredentialsMatcher AllowAllCredentialsMatcher]
           [org.apache.shiro.authz Permission SimpleAuthorizationInfo
            AuthorizationException UnauthenticatedException]
           [org.apache.shiro.subject Subject ExecutionException PrincipalCollection]
           [org.apache.shiro.subject.support SubjectCallable]
           [org.apache.shiro.web.util WebUtils]
           [org.apache.shiro.web.mgt DefaultWebSecurityManager]
           [org.apache.shiro.web.servlet ShiroHttpServletRequest]
           [org.apache.shiro.web.subject WebSubject WebSubject$Builder]
           [org.apache.shiro.util SimpleByteSource ByteSource$Util]
           [org.mindrot.jbcrypt BCrypt])
  (:require [clojure.set :as sets]
            [clojure.string :as string]))

(defn ^Subject get-bound-subject
  "Gets the subject bound to the currently executing thread.

  Use *very* sparingly."
  []
  (SecurityUtils/getSubject))

(defn- create-web-subject [manager req resp]
  (.buildWebSubject (WebSubject$Builder. manager req resp)))

(defn- save-request-and-redirect [request url]
  (let [s-request (:servlet-request request)
        s-response (:servlet-response request)]
    (WebUtils/saveRequest s-request)
    (WebUtils/issueRedirect s-request s-response url)
    {}))  ;Return something to make ring happy

(defn- execute-handler [handler request subject failure-handler login-page]
  (let [handler-callable
        (SubjectCallable. subject
          #(try
             (handler request)
             (catch AuthorizationException e
               (if (.isAuthenticated (get-bound-subject))
                 (failure-handler request e)
                 (save-request-and-redirect request login-page)))))]
    (.call handler-callable)))

(defn- non-session-encoding-response [s-response]
  ; Do not encode JSESSIONID into the url matrix
  (proxy [javax.servlet.http.HttpServletResponseWrapper] [s-response]
    (encodeURL [url] url)
    (encodeUrl [url] url)
    (encodeRedirectURL [url] url)
    (encodeRedirectUrl [url] url)))

(defn wrap-principal
  "Attaches the primary principal of the bound subject to the request under the
  given key (`:user` by default).

  Must be placed after `wrap-security`."
  [handler & {:keys [principal-key] :or {principal-key :user}}]
  (fn [request]
    (let [^Subject subject (get-bound-subject)]
      (handler (assoc request principal-key (.getPrincipal subject))))))

(defn wrap-security
  "Mimics ShiroFilter by executing the wrapped handler with a bound Shiro
  `Subject`. Depends on the servlet request/response being present in the
  request map (as provided by `ring.servlet`).

  May be customized by passing a map with the following parameters:

  - `:security-manager-retriever` - (Required) function which retrieves a
  security manager. Executed on every request. Gets passed the current request
  as a parameter.
  - `:login-page` - page the user should be redirected to on unauthorized
  access. Defaults to `/login`.
  - `:authorization-failure-handler` - function which gets invoked with a
  request and the `AuthorizationException` when authorization fails for an
  authenticated subject. By default returns the `403` response with the
  exception message as the body."
  [handler {:keys [login-page security-manager-retriever
                   authorization-failure-handler]
            :or {login-page "/login"
                 authorization-failure-handler
                 (fn [_ e] {:status 403, :body (.getMessage e)})}}]
  (fn [request]
    (let [s-request (:servlet-request request)
          s-context (:servlet-context request)
          shiro-request (ShiroHttpServletRequest. s-request s-context true)
          ; only need to wrap into Shiro response when using non-http sessions
          s-response (non-session-encoding-response (:servlet-response request))
          sec-manager (security-manager-retriever request)
          subject (create-web-subject sec-manager shiro-request s-response)
          request' (assoc request :servlet-response s-response)]
      (try
        (execute-handler handler request' subject
                         authorization-failure-handler login-page)
        (catch ExecutionException e (throw (.getCause e)))))))

(defn redirect-after-login!
  " Sends a redirect to the url accessed by the user prior to the login (or the
  supplied `fallback-url` if the user accessed the login page directly). Should
  be called after a successful login action.

  Redirect is written directly to the `ServletResponse`."
  [request fallback-url]
  (WebUtils/redirectToSavedRequest
    (:servlet-request request) (:servlet-response request) fallback-url))

(defn wrap-enforce
  "Access rule combinator to be used inside your route definitions. Works best
  with Compojure's `context` route grouping.

  - `auth-fn` - authorization function which should be composed out of the
  provided combinators (e.g. `authenticated`, `or*`, `and*`, etc.)
  - `handler` - function accepting a request (usually a valid compojure route)

  Example:

      (wrap-enforce (or* (authorized {:roles #{:manager}})
                         (authorized #(auth/is-allowed? (:id params))))
                   routes/user-routes)"
  [auth-fn handler]
  (fn [request]
    (auth-fn)
    (handler request)))

(defmacro enforce
  "Macro which executes the `body` only when the access rules pass.

  Can be used anywhere the Shiro Subject is bound to the executing thread.

  Example:

      (enforce (authorized {:roles #{:manager}})
               (users/get-all))"
  [auth-fn & body]
  `(do (~auth-fn)
       ~@body))

(defn- join-messages [exceptions]
  (string/join ", " (map #(.getMessage %) exceptions)))

(defn or*
  "Access rule which allows access in case any of the component rules allows
  access.

  Example:

      (wrap-enforce (or* (authorized {:roles #{:manager}})
                         (authorized #(auth/is-allowed? (:id params))))
                    routes/user-routes)"
  [& checks]
  (fn []
    (let [result (for [check checks]
                   (try (check) nil
                        (catch Throwable t t)))]
      (if (not-any? nil? result)
        (let [exceptions (remove nil? result)]
          (throw (AuthorizationException. (join-messages exceptions)
                                          (first exceptions))))))))

(defn and*
  "Access rule which allows access in case all of the component rules allow
  access. Fails on the first failed auth check.

  Example:

      (wrap-enforce (and* (authorized {:roles #{:manager}})
                          (authorized #(auth/is-allowed? (:id params))))
                    routes/user-routes)"
  [& checks]
  #(doseq [check checks] (check)))

(defn authenticated
  "Access rule which allows access when subject is authenticated.

  Example:

      (wrap-enforce authenticated routes/user-routes)"
  []
  (if-not (.isAuthenticated (get-bound-subject))
    (throw (AuthorizationException. "Subject is not authenticated."))))

(defn authorized
  "Access rule which allows access if subject has all of the provided
  roles/permissions or if the result of a predicate argument is truthy.

  Example:

      (enforce (authorized {:roles #{:manager}
                            :permissions #{:get-all-users})
               (users/get-all))

  or

      (wrap-enforce (authorized #(auth/is-allowed? (:id params))
                                \"Not allowed\")
                    routes/user-routes)"
  [check & description]
  (fn []
    (if (map? check)
      (let [subject (get-bound-subject)]
        (when (:roles check)
          (.checkRoles subject (set (map name (:roles check)))))
        (when (:permissions check)
          (.checkPermissions subject
            (into-array String (set (map name (:permissions check)))))))
      (if-not (check)
        (throw (AuthorizationException. (or (first description)
                                            "Custom check failed.")))))))

(defn login!
  "Logs in the subject bound to the current thread.

  Must be used after executing the shiro middleware."
  [^AuthenticationToken token]
  (let [subject (get-bound-subject)
        saved-request (WebUtils/getSavedRequest nil)]
    ; Prevent session fixation
    (-> subject .getSession .stop)
    (.login subject token)
    (-> subject .getSession
        (.setAttribute WebUtils/SAVED_REQUEST_KEY saved-request))))

(defn logout!
  "Logs out the subject bound to the current thread.

  Must be used after executing the shiro middleware."
  []
  ; Session stopped by Shiro automatically
  (.logout (get-bound-subject)))

(defn defrealm-fn
  "Defines an authenticating and authorizing Shiro realm. Realms are like
  gatekeepers who know everything about the subjects living behind their gates.
  You can have several realms in your application, e.g. `DatabaseRealm` or
  `LdapRealm`. For more info see
  [Shiro Realm documentation](http://shiro.apache.org/realm.html).

  - `:get-authentication` - a function which is given an `AuthenticationToken`
  and returns a map containing a `:principal`, probably some `:credentials` and
  a byte array/string/input stream of `:salt`. This one is mandatory.
  - `:get-authorization` - a function which is given a `PrincipalCollection` and
  returns a map containing a seq of `:roles` and/or `:permissions`. Defaults to
  no roles or permissions.
  - `:supports?` - a predicate which accepts an `AuthenticationToken` and tells
  whether this realm accepts given token. Defaults to true."
  [realm-name ^CredentialsMatcher cred-matcher &
   {:keys [supports? get-authentication get-authorization]
    :or {supports? (constantly true), get-authorization (constantly nil)}}]
  {:pre [realm-name cred-matcher get-authentication]}
  (proxy [AuthorizingRealm] [cred-matcher]
    (supports [^AuthenticationToken token] (supports? token))
    (doGetAuthenticationInfo [^AuthenticationToken token]
      (if-let [{:keys [principal credentials salt]} (get-authentication token)]
        (SimpleAuthenticationInfo. principal credentials
                                   (when salt (SimpleByteSource. salt))
                                   (str realm-name))))
    (doGetAuthorizationInfo [^PrincipalCollection pcs]
      (if-let [{:keys [roles permissions]} (get-authorization pcs)]
        (let [is-obj (partial instance? Permission)
              obj-perms (filter is-obj permissions)
              str-other-perms (map name (remove is-obj permissions))
              str-roles (map name roles)]
          (doto (SimpleAuthorizationInfo. (set str-roles))
            (.setStringPermissions (set str-other-perms))
            (.setObjectPermissions (set obj-perms))))))))

(defn iterated-hashed-passwords
  "Creates a password service which uses SHA-256 with 500,000 iterations by
  default.

  See [comments from the lead of Shiro](https://issues.apache.org/jira/browse/SHIRO-290)
  regarding the security of this approach compared to bcrypt."
  [{:keys [hash-algo hash-iterations]
    :or {hash-algo "SHA-256"
         hash-iterations (* 500 1000)}}]
  (let [dps (DefaultPasswordService.)]
    (doto (.getHashService dps)
      (.setHashAlgorithmName hash-algo)
      (.setHashIterations hash-iterations))
    dps))

(defn bcrypt-passwords
  "Creates a password service which uses bcrypt with a configurable work factor
  (default of 12)."
  [{:keys [work-factor] :or {work-factor 12}}]
  (reify PasswordService
    (encryptPassword [_ plaintext]
      (let [bytesource (ByteSource$Util/bytes plaintext)]
        (BCrypt/hashpw (String. (.getBytes bytesource))
                       (BCrypt/gensalt work-factor))))
    (passwordsMatch [_ submitted encrypted]
      (let [bytesource (ByteSource$Util/bytes submitted)]
        (BCrypt/checkpw (String. (.getBytes bytesource)) encrypted)))))

(defn username-password-realm
  "Defines a realm which allows authentication with a username/password.

  Works with Shiro's default `UsernamePasswordToken`. By default
  `iterated-hashed-passwords` matcher is used for credentials matching, which
  uses SHA-256 with 500,000 iterations on the salted password. Salt is stored
  together with a hashed password in the credentials string.

  Accepts the same set of parameters as `defrealm-fn` but provides the default
  for `realm-name`."
  [& {:keys [supports? get-authentication get-authorization
             realm-name passwords]
      :or {realm-name "up-realm"
           passwords (iterated-hashed-passwords {})
           supports? (partial instance? UsernamePasswordToken)}}]
  (defrealm-fn realm-name (doto (PasswordMatcher.)
                            (.setPasswordService passwords))
    :supports? supports?
    :get-authentication get-authentication
    :get-authorization get-authorization))
