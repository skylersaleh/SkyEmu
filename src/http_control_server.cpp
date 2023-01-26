extern "C"{
    #include "http_control_server.h"
};
#include "httplib.h"
#include <thread>
#include <iostream>
#include <sstream>
#include <vector>
struct HCSServer{
    hcs_callback callback; 
    httplib::Server svr;
    std::recursive_mutex mutex;
    std::thread thread;
    int64_t port; 
    static void server_thread(HCSServer* server){
        server->svr.set_pre_routing_handler([server](const httplib::Request& req, httplib::Response& res) {
            std::vector<const char*> params;
            for(auto &v :req.params){
                params.push_back(v.first.c_str());
                params.push_back(v.second.c_str());
                std::cout<<v.first<<" "<<v.second<<std::endl;
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
        server->svr.listen("localhost",server->port);
        std::cout<<"Terminating HCS: http://localhost:"<<server->port<<std::endl;
    }
    HCSServer(int64_t port, hcs_callback call){
        callback = call; 
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
            delete server;
            server = NULL;
        }
        if(!server&&enable){
            server = new HCSServer(port, callback);
            server->mutex.lock();
        }
        if(server)server->mutex.unlock();
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