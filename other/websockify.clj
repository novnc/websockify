(ns websockify
  (:use compojure.core,
        ring.adapter.jetty,
        aleph.http,
        aleph.tcp,
        aleph.http.core,
        lamina.core)
  (:require [compojure.route :as route]
            [aleph.formats])
  (:import  [org.jboss.netty.handler.codec.base64 Base64])

  (:use [clojure.java.io :only (file)])

  (:import [java.net URL URI]))

(def settings (atom {}))

;; WebSockets
(def clients (atom {}))

;(defn base64-encode
;  "Encodes the data into a base64 string representation."
;  [data]
;  (when data
;    (-> data to-channel-buffer Base64/encode
;    channel-buffer->string)))
;
;(defn base64-decode
;  "Decodes a base64 encoded string into bytes."
;  [string]
;  (when string
;    (-> string string->channel-buffer Base64/decode)))


(defn receive-client-msg [client target b64]
  (if b64
    (try 
      (println "Client b64 data: " b64)
      (let [raw (aleph.formats/base64-decode b64)]
        (do
          (println "Sending to target: " (pr-str (.toString raw "latin1")))
          (println "Sending to target: " (map #(mod % 256) (into-array ^char (.array raw))))
          (enqueue target (.array raw))))
      (catch Exception e (println e)))
    (do
      (println "Client Closed")
      (swap! clients dissoc client)
      (close target)
      (close client))))

(defn receive-target-msg [client target raw]
  (if raw
    (try 
      (println "Target raw data: " (pr-str (aleph.formats/bytes->string raw "latin1")))
      (println "Target raw class: " (class raw))
      (println "Target raw array: " (.array raw))
      (println "Target raw data: " (map #(mod % 256) (into-array ^char (.array raw))))
      (let [b64 (aleph.formats/base64-encode raw)]
        (do
          (println "Sending to client: " b64)
          (enqueue client b64)))
      (catch Exception e (println e)))
    (do
      (println "Target Closed")
      (swap! clients dissoc client)
      (close client)
      (close target))
      ))

(defn ws-handler [client handshake]
  (let [target-host (@settings :target-host)
        target-port (@settings :target-port)
        target @(tcp-client {:host target-host, :port target-port})]
    (println "Connected to target")
    (println "client: " (class client) ", target: " (class target))
    (receive-all client #(receive-client-msg client target %))
    (println "Started receive-client-msg")
    (receive-all target #(receive-target-msg client target %))
    (println "Started receive-target-msg")
    (swap! clients assoc client target)))

;; HTTP
(defn get-routes [root]
  (defroutes main-routes
    (GET "*" {websocket :websocket}
         (when websocket (wrap-aleph-handler ws-handler)))
    
    (route/files "/"
      {:root root}
      (route/not-found (file "www/404.html")))
    (route/not-found "<h1>Page not found</h1>")))

(defn start
  "Start websockify
   :listen-port - port to start server on (default 6080)
   :opts - map of Noir server options"
  [& {:keys [listen-port target-host target-port web opts]
      :or {listen-port 6080
           target-host "localhost"
           target-port 5900
           web "./"
           opts {}}}]

  (reset! settings {:target-host target-host
                    :target-port target-port})
  (def stop
    (let [stop (start-http-server (wrap-ring-handler (get-routes web))
                                  {:port listen-port :websocket true})]
      (fn [] (stop)))))
