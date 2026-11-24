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
        server->svr.set_tcp_nodelay(true);
        server->svr.set_pre_routing_handler([server](const httplib::Request& req, httplib::Response& res) {
            std::vector<std::string> params_store;
            auto &args = req.target;
            int state = 0; //Query not found
            std::string chunk = "";
            auto flush_chunk = [&params_store](std::string & str){
                params_store.push_back(httplib::detail::decode_url(str, true));
                str="";
            };
            for(size_t s = 0; s< args.size();++s){
                switch(state){
                    case 0: //Query not found
                        if(args[s]=='?') state = 1; 
                        break;
                    case 1: //Key
                        if(args[s]=='='){
                            flush_chunk(chunk);
                            state = 2; 
                        }else if(args[s]=='&'){
                            if(chunk.length()){
                                flush_chunk(chunk);
                                flush_chunk(chunk);
                            }
                            state =1; 
                        }else chunk+=args[s];
                        break;
                    case 2: // value
                        if(args[s]=='&'){
                            flush_chunk(chunk);
                            state = 1; 
                        }else chunk+=args[s];
                        break;
                }
            }
            if(state==1 && chunk.length()){
                flush_chunk(chunk);
                flush_chunk(chunk);
            }
            if(state==2)flush_chunk(chunk);

            std::vector<const char*> params;
            for(auto & p : params_store) params.push_back(p.c_str());


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