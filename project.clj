(defproject pocheshiro "0.1.2-SNAPSHOT"
  :description "Clojure wrapper for Apache Shiro"
  :min-lein-version "2.0.0"
  :dependencies [[org.apache.shiro/shiro-web "1.2.2"]
                 [org.mindrot/jbcrypt "0.3m"]]
  :license {:name "MIT License"
            :url "http://choosealicense.com/licenses/mit/"}
  :url "http://github.com/inventiLT/Pocheshiro"
  :scm {:name "git"
        :url "http://github.com/inventiLT/Pocheshiro"}
  :profiles {:dev {:dependencies [[org.clojure/clojure "1.5.1"]
                                  [compojure "1.1.5"]
                                  [javax.servlet/servlet-api "2.5"]]}})
