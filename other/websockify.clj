(ns websockify
  (:use ring.adapter.jetty)
  ;(:import  [org.jboss.netty.handler.codec.base64 Base64])

           
  (:import
   ;[java.io BufferedReader DataOutputStream]

   [java.net InetSocketAddress]
   [java.nio ByteBuffer]
   [java.nio.channels SocketChannel]

   [org.jboss.netty.channel
    Channels SimpleChannelHandler ChannelPipelineFactory]
   [org.jboss.netty.channel.socket.nio NioClientSocketChannelFactory]
   [org.jboss.netty.bootstrap ClientBootstrap]
   [java.util.concurrent Executors]
   
   [org.eclipse.jetty.server Server]
   [org.eclipse.jetty.server.nio BlockingChannelConnector]
   [org.eclipse.jetty.servlet ServletContextHandler ServletHolder DefaultServlet]
   [org.eclipse.jetty.websocket
     WebSocket WebSocketClientFactory WebSocketClient
     WebSocketServlet]))

(defonce settings (atom {}))

;; TCP / NIO

;; (defn tcp-channel [host port]
;;   (try
;;     (let [address (InetSocketAddress. host port)
;;          channel (doto (SocketChannel/open)
;;                    (.connect address))]
;;       channel)
;;     (catch Exception e
;;       (println (str "Failed to connect to'" host ":" port "':" e))
;;       nil)))

;; http://docs.jboss.org/netty/3.2/guide/html/start.html#d0e51
(defn make-netty-client-handler []
  (proxy [SimpleChannelHandler] []
    (channelConnected [ctx e]
      (println "channelConnected:" e))
    (channelDisconnected [ctx e]
      (println "channelDisconnected:" e))
    (messageReceived [ctx e]
      (println "messageReceived:" (.getMessage e)))
    (exceptionCaught [ctx e]
      (println "exceptionCaught:" e))))

(defn netty-client [host port]
  (let [pipeline (proxy [ChannelPipelineFactory] []
                   (getPipeline []
                     (doto (Channels/pipeline)
                       (.addLast "handler" (make-netty-client-handler)))))
        bootstrap (doto (ClientBootstrap.
                         (NioClientSocketChannelFactory.
                          (Executors/newCachedThreadPool)
                          (Executors/newCachedThreadPool)))
                    (.setPipelineFactory pipeline)
                    (.setOption "tcpNoDelay" true)
                    (.setOption "keepAlive" true))
        channel-future (.connect bootstrap (InetSocketAddress. host port))
        channel (.. channel-future (awaitUninterruptibly) (getChannel))]
    channel))



;; WebSockets


(defonce clients (atom {}))

;; http://wiki.eclipse.org/Jetty/Feature/WebSockets
(defn make-websocket-handler []
  (reify org.eclipse.jetty.websocket.WebSocket$OnTextMessage
    (onOpen [this connection]
      (println "Got WebSocket connection:" connection)
      #_(let [target (tcp-channel "localhost" 5901)]
        (swap! clients assoc this {:client connection
                                   :target target})))
    (onClose [this code message]
      (println "Got WebSocket close:" code message)
      (swap! clients dissoc this))
    (onMessage [this data]
      (println "Got WebSocket message:" data))))

(defn make-websocket-servlet []
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
        ws-servlet (ServletHolder. (make-websocket-servlet))
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

