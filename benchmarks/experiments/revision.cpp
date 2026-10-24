#include <bits/stdc++.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <type_traits>
using namespace std;


template<typename T,size_t initalCapcity = 8>
class SmallVector{

    private:
        int capacity;
        int size ; 
        T * data;
        alignas(alignof(T)) char inlineBuffer_[sizeof(T) * initalCapcity];

    public:
        SmallVector(int cap,int s){
            this->capacity = cap;
            this->size = s;
            this->data = reinterpret_cast<T*>(inlineBuffer_);
        }

        void reallocate(int new_capacity){
            T* new_buffer = reinterpret_cast<T*>(malloc(sizeof(T) * new_capacity));
            if constexpr (std::is_trivially_copyable<T>::value){
                std::memcpy(new_buffer,)
            }
        }


};