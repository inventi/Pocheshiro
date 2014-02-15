# Pocheshiro

[![Build Status](https://travis-ci.org/inventiLT/Pocheshiro.png?branch=master)](https://travis-ci.org/inventiLT/Pocheshiro)

Pocheshiro is a Clojure wrapper for the [Apache
Shiro](http://shiro.apache.org/) security library tailored for use with
[Ring](https://github.com/ring-clojure/ring) and
[Compojure](https://github.com/weavejester/compojure).

Pocheshiro must be run in a servlet container (sorry, no
[http-kit](http://http-kit.org/) because Shiro depends on the servlet
specification).

### Motivation

If you're coming from Java-land, you've probably used either [Spring
Security](http://projects.spring.io/spring-security/) or Apache Shiro.

Jumping from one of these straight to
[Friend](https://github.com/cemerick/friend), which is the mainstream Clojure
option for securing web applications, may be too big of a leap. After all,
security is a sensitive part of any application.

### Usage

```clj
[pocheshiro "0.1.1"]
```
Pocheshiro is a thin wrapper so you will need to use some of the Shiro classes
directly.  Let's see what we're going to need in order to provided a
username/password authentication with role and permission authorization
capabilities.

#### Choosing a password service

In order to register new users you will have to store their identifying
attributes (principal in Shiro parlance) and passwords (credentials).  You can
choose either [Bcrypt](http://en.wikipedia.org/wiki/Bcrypt) or salted and
iterated [SHA](http://en.wikipedia.org/wiki/Secure_Hash_Algorithm) for your
password hashing needs.

```clj
(require '[pocheshiro.core :as shiro])

(def users (atom {}))

(def bcrypted-passwords (shiro/bcrypt-passwords {}))

(defn register-user! [{:keys [username password
                              roles permissions]}]
  (let [hashed-pwd (.encryptPassword bcrypted-passwords password)]
    (swap! users assoc username {:username username
                                 :roles (set roles)
                                 :permissions (set permissions)
                                 :password-hash hashed-pwd})))

(register-user! {:username "john"
                 :password "secret"
                 :roles [:manager]
                 :permissions [:fire-underlings]})
```

#### Defining the realms

[Realms](http://shiro.apache.org/realm.html) are the core part of Shiro.
According to Shiro docs, a Realm is a

> component that can access application-specific security data such as users,
> roles, and permissions. The Realm translates this application-specific data
> into a format that Shiro understands so Shiro can in turn provide a single
> easy-to-understand Subject programming API no matter how many data sources
> exist or how application-specific your data might be.

Basically, a realm takes user attributes and credentials and looks up the
authentication/authorization info for the user.

Pocheshiro provides a way to concisely define realms via the `defrealm-fn`
function together with a stub handling username/password authentication -
`username-password-realm`.

```clj
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
```

#### Defining the middleware

The wiring of the Shiro library is concentrated in the
[SecurityManager](http://shiro.apache.org/securitymanager.html).  Here you will
set all of the settings, add listeners and other options provided by Shiro.

Web applications will need an instance of `WebSecurityManager`.

```clj
(import 'org.apache.shiro.web.mgt.DefaultWebSecurityManager)
(require '[compojure.handler :as handler])

(def security-manager (DefaultWebSecurityManager. [inmemory-realm]))

(declare main-routes)

(def app
  (shiro/wrap-security
    (shiro/wrap-principal (handler/site #'main-routes))
    {:security-manager-retriever (constantly security-manager)}))
```

Security manager is retrieved in a function in order to facilitate extracting
it from the `system` contained in the request, [Stuart Sierra
style](https://github.com/stuartsierra/reloaded).

#### Logging in and out

First, import the type of token we'll be using for authentication.
`UsernamePasswordToken` is supported by the `username-password-realm` by
default.

```clj
(import 'org.apache.shiro.authc.UsernamePasswordToken)
```

We'll need to define routes for logging in and out. Notice the
`redirect-after-login!` call which happens after `login!`. This call will send
a redirect to the URI visited before being redirected to the login page (or the
*/index* page if you went straight to the login):

```clj
(require '[compojure.core :refer [GET POST context defroutes]])

(defroutes main-routes
  (POST "/login" {:keys [params] :as request}
    (shiro/login! (UsernamePasswordToken. (:username params)
                                          (:password params)))
    (shiro/redirect-after-login! request "/index"))

  (GET "/logout" request
    (shiro/logout!)
    {:status 200, :body "You have been logged out!"})

  ...
```

#### Protecting the routes

```clj
(require '[pocheshiro.core :as shiro :refer
            [enforce wrap-enforce authorized authenticated or*]])

(defroutes manager-routes ... )

(defroutes main-routes
  ...

  (GET "/managers-only" request
    (wrap-enforce (authorized {:roles #{:manager}})
                  manager-routes)

  ; We can extract the primary principal from the request if the
  ; `wrap-principal` middleware was used when defining the Ring handler.
  ; In this case `user` is equal to the username provided to the
  ; `register-user!` above (as that's what we return from the realm).
  (GET "/anonymous-only-at-midnight" [{:keys [user]}]
    (enforce (or* authenticated
                  (authorized #(= dates/midnight (dates/now))))
             (views/at-midnight user))))
```

### Configuring the servlet container

In order to use Pocheshiro you will need to run your Ring/Compojure app as a
servlet. If you already produce a **WAR** artifact, you don't need to modify
anything, but if you run in a `Jetty`, you will need to configure it properly:

```clj
(import '[org.eclipse.jetty.servlet ServletContextHandler ServletHolder])
(require '[ring.adapter.jetty :as jetty]
         '[ring.util.servlet :as servlet])

(defn run [handler]
  (jetty/run-jetty handler
    {:port 8080
     :configurator
       #(.setHandler %
          (doto (ServletContextHandler.)
            (.addServlet (ServletHolder. (servlet/servlet handler)) "/*")))})))
```

### License

Licensed under MIT License.
