#include <chrono>
#include <cmath>
#include <mutex>
#include <algorithm>
#include <iostream>

class TokenBucket{
    // capacity max token the bucket can hold
    // refill rate tokens added per seoncd
    private:
        using Clock = std::chrono::steady_clock;
        double capacity_;
        double refill_rate_;
        double tokens_;
        Clock::time_point last_refill_;
        std::mutex mutex_;

        void refill(){
            auto now = Clock::now();
            std::chrono::duration<double> elapsed = now - last_refill_;

            tokens_ = std::min(capacity_, tokens_ + elapsed.count() * refill_rate_);
            last_refill_ = now;
        }

    public:
    TokenBucket(double capacity, double refill_rate){
        this->capacity_ = capacity;
        this->refill_rate_ = refill_rate;
        this->tokens_ = capacity;
        this->last_refill_ = Clock::now();
    };

    bool allow(double n = 1.0){
        std::lock_guard<std::mutex> lock(mutex_);
        refill();
        if(tokens_ >=n){
            tokens_-=n;
            return true;
        }
        return false;
    }

};

class EWMA{
    private:
    using Clock = std::chrono::steady_clock;
    double tau_;
    double value_;
    bool initialized_;
    Clock::time_point last_update_;
    mutable std::mutex mutex_;

    public:
        explicit EWMA(double tau_seconds){
            this->tau_ = tau_seconds;
            this->value_ = 0.0;
            this->initialized_ = false;
            this->last_update_ = Clock::now();

        }

        void update(double sample){
            std::lock_guard<std::mutex> lock(mutex_);
            auto now = Clock::now();

            double dt = std::chrono::duration<double>(now - last_update_).count();
            last_update_ = now;


            if(!initialized_){
                value_ = sample;
                initialized_ = true;
                return;
            }


            double alpha = 1.0 - std::exp(-dt/tau_);
            value_ = alpha * sample + (1.0 - alpha) * value_;
        }

        double value() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return value_;
        }

};



int main(){
    TokenBucket limiter(100,20);

    return 0;
}