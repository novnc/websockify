(ns websockify
  (:use ring.adapter.jetty)

  (:import
   ;; Netty TCP Client 
   [java.util.concurrent Executors]
   [java.net InetSocketAddress]
   [org.jboss.netty.channel
    Channels SimpleChannelHandler ChannelPipelineFactory]
   [org.jboss.netty.buffer ChannelBuffers]
   [org.jboss.netty.channel.socket.nio NioClientSocketChannelFactory]
   [org.jboss.netty.bootstrap ClientBootstrap]
   [org.jboss.netty.handler.codec.base64 Base64]
   [org.jboss.netty.util CharsetUtil]
   
   ;; Jetty WebSocket Server
   [org.eclipse.jetty.server Server]
   [org.eclipse.jetty.server.nio BlockingChannelConnector]
   [org.eclipse.jetty.servlet
    ServletContextHandler ServletHolder DefaultServlet]
   [org.eclipse.jetty.websocket
     WebSocket WebSocketClientFactory WebSocketClient
     WebSocketServlet]))

(defonce settings (atom {}))

;; WebSocket client to TCP target mappings

(defonce clients (atom {}))
(defonce targets (atom {}))


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
;; http://stackoverflow.com/questions/5453602/highly-concurrent-http-with-netty-and-nio
;; https://github.com/datskos/ring-netty-adapter/blob/master/src/ring/adapter/netty.clj


(defn netty-client [host port open close message]
  (let [handler (proxy [SimpleChannelHandler] []
                  (channelConnected [ctx e] (open ctx e))
                  (channelDisconnected [ctx e] (close ctx e))
                  (messageReceived [ctx e] (message ctx e))
                  (exceptionCaught [ctx e]
                    (println "exceptionCaught:" e)))
        pipeline (proxy [ChannelPipelineFactory] []
                   (getPipeline []
                     (doto (Channels/pipeline)
                       (.addLast "handler" handler))))
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

(defn target-open [ctx e]
  (println "Connected to target")
  #_(println "channelConnected:" e))
(defn target-close [ctx e]
  #_(println "channelDisconnected:" e)
  (println "Target closed")
  (when-let [channel (get @targets (.getChannel ctx))]
    (.disconnect channel)))
(defn target-message [ctx e]
  (let [channel (.getChannel ctx)
        client (get @targets channel)
        msg (.getMessage e)
        len (.readableBytes msg)
        b64 (Base64/encode msg false)
        blen (.readableBytes b64)]
    #_(println "received" len "bytes from target")
    #_(println "target receive:" (.toString msg 0 len CharsetUtil/UTF_8))
    #_(println "sending to client:" (.toString b64 0 blen CharsetUtil/UTF_8))
    (.sendMessage client (.toString b64 0 blen CharsetUtil/UTF_8))))


;; http://wiki.eclipse.org/Jetty/Feature/WebSockets
(defn make-websocket-handler []
  (reify org.eclipse.jetty.websocket.WebSocket$OnTextMessage
    (onOpen [this connection]
      #_(println "Got WebSocket connection:" connection)
      (println "New client")
      (let [target (netty-client
                    "localhost" 5901
                    target-open target-close target-message)]
        (swap! clients assoc this {:client connection
                                   :target target})
        (swap! targets assoc target connection)))
    (onClose [this code message]
      (println "WebSocket connection closed")
      (when-let [target (:target (get @clients this))]
        (println "Closing target")
        (.close target)
        (println "Target closed")
        (swap! targets dissoc target))
      (swap! clients dissoc this))
    (onMessage [this data]
      #_(println "WebSocket onMessage:" data)
      (let [target (:target (get @clients this))
            cbuf (ChannelBuffers/copiedBuffer data CharsetUtil/UTF_8)
            decbuf (Base64/decode cbuf)
            rlen (.readableBytes decbuf)]
        #_(println "Sending" rlen "bytes to target")
        #_(println "Sending to target:" (.toString decbuf 0 rlen CharsetUtil/UTF_8))
        (.write target decbuf)))))

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
  (reset! clients {})
  (reset! targets {})
  (let [http-servlet (doto (ServletHolder. (DefaultServlet.))
                      (.setInitParameter "dirAllowed" "true")
                      (.setInitParameter "resourceBase" web))
        ws-servlet (ServletHolder. (make-websocket-servlet))
        context (doto (ServletContextHandler.)
                  (.setContextPath "/")
                  (.addServlet ws-servlet "/websockify"))
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
      (doseq [client (vals @clients)]
        (.disconnect (:client client))
        (.close (:target client)))
      (.stop server)
      (reset! clients {})
      (reset! targets {})
      nil)))

