#include <stdint.h>
#include <stdio.h>

#include <fuzzer/FuzzedDataProvider.h>
extern "C"
{
#include "xlsxwriter.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    const char *cstr = str.c_str();
    char* n = lxw_quote_sheetname(cstr);
    free(n);

    return 0;
}
