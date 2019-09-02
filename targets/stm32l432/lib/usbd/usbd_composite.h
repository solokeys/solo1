#ifndef __USB_COMPOSITE_H
#define __USB_COMPOSITE_H

#ifdef __cplusplus
 extern "C" {
#endif

#include "usbd_ioreq.h"

#define MAX_CLASSES 4

#define MAX_ENDPOINTS 16

extern USBD_ClassTypeDef USBD_Composite;

extern int in_endpoint_to_class[MAX_ENDPOINTS];

extern int out_endpoint_to_class[MAX_ENDPOINTS];

void USBD_Composite_Set_Classes(USBD_ClassTypeDef *class0, USBD_ClassTypeDef *class1, USBD_ClassTypeDef *class2);

#ifdef __cplusplus
}
#endif

#endif
