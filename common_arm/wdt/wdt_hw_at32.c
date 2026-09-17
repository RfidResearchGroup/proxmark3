#include "wdt_apis.h"

void WDTSetup(void) {
    // TODO DXL 待实现，记得尽量把时间拉长一些，让某些耗时堵塞逻辑不会导致看门狗复位
    //  特别关注flash相关的操作，在AT91上会在操作FLASH之前禁用看门狗，但是AT32是无法禁用看门狗的
}
