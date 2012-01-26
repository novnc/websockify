(ns websockify
  (:use ring.adapter.jetty)
  ;(:import  [org.jboss.netty.handler.codec.base64 Base64])

  (:import [java.net URL URI]
   [org.eclipse.jetty.server Server]
   [org.eclipse.jetty.server.nio BlockingChannelConnector]
   [org.eclipse.jetty.servlet ServletContextHandler ServletHolder DefaultServlet]
   [org.eclipse.jetty.websocket
     WebSocket WebSocketClientFactory WebSocketClient
     WebSocketServlet]))

(defonce settings (atom {}))

;; WebSockets
(defonce clients (atom {}))


(defn make-websocket-handler []
  (reify org.eclipse.jetty.websocket.WebSocket$OnTextMessage
    (onOpen [this connection]
      (println "Got WebSocket connection:" connection)
      (swap! clients assoc this connection))
    (onClose [this code message]
      (println "Got WebSocket close:" code message)
      (swap! clients dissoc this))
    (onMessage [this data]
      (println "Got WebSocket message:" data))))

(defn websocket-servlet []
  (proxy [org.eclipse.jetty.websocket.WebSocketServlet] []
    (doGet [request response]
      ;(println "doGet" request)
      (.. (proxy-super getServletContext)
          (getNamedDispatcher (proxy-super getServletName))
          (forward request response)))
    (doWebSocketConnect [request response]
      (println "doWebSocketConnect")
      (make-websocket-handler))))

(defn start-websocket-server
  [& {:keys [listen-port target-host target-port web]
      :or {listen-port 6080
           target-host "localhost"
           target-port 5900
           }}]
  (let [http-servlet (doto (ServletHolder. (DefaultServlet.))
                      (.setInitParameter "dirAllowed" "true")
                      (.setInitParameter "resourceBase" web))
        ws-servlet (ServletHolder. (websocket-servlet))
        context (doto (ServletContextHandler.)
                  (.setContextPath "/")
                  (.addServlet ws-servlet "/websocket"))
        connector (doto (BlockingChannelConnector.)
                    (.setPort listen-port)
                    (.setMaxIdleTime Integer/MAX_VALUE))
        server (doto (Server.)
                 (.setHandler context)
                 (.addConnector connector)
                 (.start))]
    (if web
      (do
        (println "Serving web requests from:" web)
        (.addServlet context http-servlet "/"))
      (println "Not serving web requests"))
    
    (defn stop []
      (.stop server))))

