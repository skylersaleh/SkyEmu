extern "C"{
    #include "http_control_server.h"
};
#include "httplib.h"
#include <thread>
#include <iostream>
#include <sstream>
#include <vector>
#include <chrono>
struct HCSServer{
    hcs_callback callback;
    hcs_stream_callback stream_callback;
    httplib::Server svr;
    std::recursive_mutex mutex;
    std::thread thread;
    int64_t port; 
    static void server_thread(HCSServer* server){
        server->svr.set_tcp_nodelay(true);
        
        // Register /stream endpoint with streaming support
        server->svr.Get("/stream", [server](const httplib::Request& req, httplib::Response& res) {
            if(!server->stream_callback) {
                res.status = 503;
                res.set_content("Streaming not available", "text/plain");
                return;
            }
            
            // Parse FPS parameter (default 30)
            int fps = 30;
            auto fps_param = req.get_param_value("fps");
            if(!fps_param.empty()) {
                try {
                    fps = std::stoi(fps_param);
                    if(fps < 1) fps = 1;
                    if(fps > 60) fps = 60;
                } catch (const std::invalid_argument&) {
                    fps = 30; // Default on invalid input
                } catch (const std::out_of_range&) {
                    fps = 30; // Default on out of range
                }
            }
            
            int frame_delay_ms = 1000 / fps;
            
            // Use multipart/x-mixed-replace for MJPEG-style streaming
            std::string boundary = "frame";
            std::string content_type = "multipart/x-mixed-replace; boundary=" + boundary;
            
            res.set_chunked_content_provider(
                content_type,
                [server, boundary, frame_delay_ms](size_t offset, httplib::DataSink& sink) {
                    uint64_t result_size = 0;
                    server->mutex.lock();
                    uint8_t* frame_data = server->stream_callback(&result_size);
                    server->mutex.unlock();
                    
                    if(!frame_data || result_size == 0) {
                        return false; // End stream
                    }
                    
                    // Send multipart frame header
                    std::ostringstream header;
                    header << "--" << boundary << "\r\n";
                    header << "Content-Type: image/jpeg\r\n";
                    header << "Content-Length: " << result_size << "\r\n\r\n";
                    
                    std::string header_str = header.str();
                    if(!sink.write(header_str.c_str(), header_str.size())) {
                        free(frame_data);
                        return false;
                    }
                    
                    // Send frame data
                    if(!sink.write((const char*)frame_data, result_size)) {
                        free(frame_data);
                        return false;
                    }
                    
                    free(frame_data);
                    
                    // Send trailing newline
                    if(!sink.write("\r\n", 2)) {
                        return false;
                    }
                    
                    // Delay to control frame rate
                    std::this_thread::sleep_for(std::chrono::milliseconds(frame_delay_ms));
                    
                    return true; // Continue streaming
                }
            );
        });
        
        server->svr.set_pre_routing_handler([server](const httplib::Request& req, httplib::Response& res) {
            // Skip /stream as it's handled by dedicated route
            if(req.path == "/stream") {
                return httplib::Server::HandlerResponse::Unhandled;
            }
            
            std::vector<const char*> params;
            for(auto &v :req.params){
                params.push_back(v.first.c_str());
                params.push_back(v.second.c_str());
            }
            params.push_back(NULL);
            params.push_back(NULL);
            bool handled = false; 
            if(server->callback){
                uint64_t result_size = 0; 
                const char *mime_type = "";
                server->mutex.lock();
                uint8_t * result = server->callback(req.path.c_str(),&params[0],&result_size, &mime_type);
                server->mutex.unlock();
                if(result&&result_size){
                    res.set_content((const char*)result,result_size,mime_type);
                    free(result);
                    return httplib::Server::HandlerResponse::Handled;
                }
            }
            return httplib::Server::HandlerResponse::Unhandled;
        });
        std::cout<<"Starting HCS: http://localhost:"<<server->port<<std::endl;
        server->svr.listen("0.0.0.0",server->port);
        std::cout<<"Terminating HCS: http://localhost:"<<server->port<<std::endl;
    }
    HCSServer(int64_t port, hcs_callback call){
        callback = call;
        stream_callback = NULL;
        this->port = port; 
        thread = std::thread(server_thread,this);
    }
    ~HCSServer(){
       svr.stop();
       thread.join();
    }
};
HCSServer * server = NULL;
extern "C"{
    void hcs_update(bool enable, int64_t port, hcs_callback callback){
        if(server)server->mutex.lock();
        if(server&&(!enable||port!=server->port)){
            server->mutex.unlock();
            delete server;
            server = NULL;
        }
        if(!server&&enable){
            server = new HCSServer(port, callback);
            server->mutex.lock();
        }
        if(server)server->mutex.unlock();
    }

    void hcs_set_stream_callback(hcs_stream_callback stream_callback){
        if(server){
            server->mutex.lock();
            server->stream_callback = stream_callback;
            server->mutex.unlock();
        }
    }

    void hcs_suspend_callbacks(){
        if(server)server->mutex.lock();
    }
    void hcs_resume_callbacks(){
        if(server)server->mutex.unlock();
    }
    void hcs_join_server_thread(){
        if(server)server->thread.join();
    }
}