#pragma once

#include "../loader/pe/PeTlsExceptions.h"
#include <cstdint>
#include <string>
#include <functional>

namespace nexus {

struct GuestException {
    uint32_t code = 0;
    uint64_t address = 0;
    std::string message;
};

using ExceptionSink = std::function<void(const GuestException&)>;

class SehDispatcher {
public:
    void setDirectory(const ExceptionInfo& info) { info_ = info; }
    void setSink(ExceptionSink sink) { sink_ = std::move(sink); }
    static void setJvm(void* vm);

    // Dispatch an exception. Finds the pdata entry covering `address` and logs it.
    // Returns true if a handler frame was found.
    bool dispatch(uint32_t code, uint64_t address, const std::string& message);

private:
    ExceptionInfo info_;
    ExceptionSink sink_;
};

} // namespace nexus
