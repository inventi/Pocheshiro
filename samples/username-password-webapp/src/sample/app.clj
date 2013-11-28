(ns sample.app
  (:import [org.eclipse.jetty.servlet ServletContextHandler ServletHolder]
           [org.eclipse.jetty.server.session SessionHandler]
           org.apache.shiro.web.mgt.DefaultWebSecurityManager
           org.apache.shiro.authc.UsernamePasswordToken)
  (:require [ring.adapter.jetty :as jetty]
            [ring.util.servlet :as servlet]

            [compojure.handler :as handler]
            [compojure.core :refer (context defroutes GET POST)]

            [pocheshiro.core :as shiro :refer (enforce authorized authenticated)]))

(defn run [handler]
  (jetty/run-jetty handler
    {:join? false
     :port 8080
     :configurator
     #(let [session-handler (SessionHandler.)]
        (-> session-handler .getSessionManager (.setHttpOnly true))
        (.setHandler
          % (doto (ServletContextHandler.)
              (.setSessionHandler session-handler)
              (.addServlet (ServletHolder. (servlet/servlet handler)) "/*"))))}))

(def users (atom {}))

(def bcrypted-passwords (shiro/bcrypt-passwords {}))

(defn register-user! [{:keys [username password roles permissions]}]
  (let [hashed-pwd (.encryptPassword bcrypted-passwords password)]
    (swap! users assoc username {:username username
                                 :roles (set roles)
                                 :permissions (set permissions)
                                 :password-hash hashed-pwd})))

(defroutes routes
  (GET "/" {:keys [user]}
       (enforce authenticated
                (str "You are logged in, " user "."
                     "<a href=\"/logout\">Logout</a>")))

  (GET "/login" request
       "<form method=\"POST\" action=\"/login\">
         <label for=\"username\">Username:
         <input type=\"text\" name=\"username\"/>
         </label>
         <label for=\"password\">Password:
         <input type=\"password\" name=\"password\"/>
         </label>
         <input type=\"submit\" value=\"Login\" />
       </form>")

  (POST "/login" {:keys [params] :as request}
        (shiro/login! (UsernamePasswordToken. (:username params) (:password params)))
        (shiro/redirect-after-login! request "/"))

  (GET "/logout" request
       (shiro/logout!)
       {:status 200, :body "You have been logged out!"}))

(def inmemory-realm
  (shiro/username-password-realm
    :passwords bcrypted-passwords
    :get-authentication
    #(if-let [user (get @users (.getPrincipal %))]
       {:principal (:username user)
        :credentials (:password-hash user)})
    :get-authorization
    #(if-let [user (get @users (.getPrimaryPrincipal %))]
       (select-keys user [:roles :permissions]))))

(def security-manager (DefaultWebSecurityManager. [inmemory-realm]))

(def route-handler
  (shiro/wrap-security
    (handler/site #'routes)
    {:security-manager-retriever (constantly security-manager)}))

(register-user! {:username "john"
                 :password "secret"
                 :roles [:manager]
                 :permissions [:fire-underlings]})

(defn run! []
  (run route-handler))
