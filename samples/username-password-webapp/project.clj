(defproject pocheshiro-sample-username-password-webapp "0.0.1-SNAPSHOT"
  :description "Example project for Pocheshiro"
  :min-lein-version "2.0.0"
  :license {:name "MIT License"
            :url "http://choosealicense.com/licenses/mit/"}
  :url "http://github.com/inventiLT/Pocheshiro/samples/username-password-webapp"
  :dependencies [[pocheshiro "0.1.1"]
                 [ring/ring-servlet "1.2.1"]
                 [ring/ring-core "1.2.1"]
                 [ring/ring-jetty-adapter "1.2.1"]
                 [org.eclipse.jetty/jetty-servlet "7.6.8.v20121106"]
                 [compojure "1.1.5"]
                 [javax.servlet/servlet-api "2.5"]]
  :profiles {:dev {:dependencies [[org.clojure/clojure "1.5.1"]]}})
