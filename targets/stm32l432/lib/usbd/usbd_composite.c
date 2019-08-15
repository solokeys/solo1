#include "usbd_composite.h"
#include "usbd_desc.h"
#include "usbd_hid.h"
#include "usbd_cdc.h"
#include "usbd_ctlreq.h"

static uint8_t USBD_Composite_Init (USBD_HandleTypeDef *pdev, uint8_t cfgidx);

static uint8_t USBD_Composite_DeInit (USBD_HandleTypeDef *pdev, uint8_t cfgidx);

static uint8_t USBD_Composite_Setup (USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req);

static uint8_t USBD_Composite_DataIn (USBD_HandleTypeDef *pdev, uint8_t epnum);

static uint8_t USBD_Composite_DataOut (USBD_HandleTypeDef *pdev, uint8_t epnum);

static uint8_t USBD_Composite_EP0_RxReady (USBD_HandleTypeDef *pdev);

static uint8_t *USBD_Composite_GetFSCfgDesc (uint16_t *length);

static uint8_t *USBD_Composite_GetHSCfgDesc (uint16_t *length);

static uint8_t *USBD_Composite_GetOtherSpeedCfgDesc (uint16_t *length);

static uint8_t *USBD_Composite_GetOtherSpeedCfgDesc (uint16_t *length);

static uint8_t *USBD_Composite_GetDeviceQualifierDescriptor (uint16_t *length);

#define NUM_CLASSES                         2
#define NUM_INTERFACES                      3

#if NUM_INTERFACES>1
#define COMPOSITE_CDC_HID_DESCRIPTOR_SIZE   (90 + 8+9 + 4)
#else
#define COMPOSITE_CDC_HID_DESCRIPTOR_SIZE   (41)
#endif

#define HID_INTF_NUM                                0
#define CDC_MASTER_INTF_NUM                         1
#define CDC_SLAVE_INTF_NUM 2
__ALIGN_BEGIN uint8_t COMPOSITE_CDC_HID_DESCRIPTOR[COMPOSITE_CDC_HID_DESCRIPTOR_SIZE] __ALIGN_END =
    {
        /*Configuration Descriptor*/
        0x09,                              /* bLength: Configuration Descriptor size */
        USB_DESC_TYPE_CONFIGURATION,       /* bDescriptorType: Configuration */
        COMPOSITE_CDC_HID_DESCRIPTOR_SIZE, /* wTotalLength:no of returned bytes */
        0x00,
        NUM_INTERFACES, /* bNumInterfaces */
        0x01,           /* bConfigurationValue: Configuration value */
        0x00,           /* iConfiguration: Index of string descriptor describing the configuration */
        0x80,           /* bmAttributes: self powered */
        0x32,           /* MaxPower 100 mA */

        /*---------------------------------------------------------------------------*/

        /*     */
        /* HID */
        /*     */

        /************** Descriptor of Joystick Mouse interface ****************/
        0x09,                    /*bLength: Interface Descriptor size*/
        USB_DESC_TYPE_INTERFACE, /*bDescriptorType: Interface descriptor type*/
        HID_INTF_NUM,            /*bInterfaceNumber: Number of Interface*/
        0x00,                    /*bAlternateSetting: Alternate setting*/
        0x02,                    /*bNumEndpoints*/
        0x03,                    /*bInterfaceClass: HID*/
        0x00,                    /*bInterfaceSubClass : 1=BOOT, 0=no boot*/
        0x00,                    /*nInterfaceProtocol : 0=none, 1=keyboard, 2=mouse*/
        2,                       /*iInterface: Index of string descriptor*/
        /******************** Descriptor of Joystick Mouse HID ********************/
        0x09,                /*bLength: HID Descriptor size*/
        HID_DESCRIPTOR_TYPE, /*bDescriptorType: HID*/
        0x11,                /*bcdHID: HID Class Spec release number*/
        0x01,
        0x00,                      /*bCountryCode: Hardware target country*/
        0x01,                      /*bNumDescriptors: Number of HID class descriptors to follow*/
        0x22,                      /*bDescriptorType*/
        HID_FIDO_REPORT_DESC_SIZE, /*wItemLength: Total length of Report descriptor*/
        0,
        /******************** Descriptor of Mouse endpoint ********************/
        0x07,                   /*bLength: Endpoint Descriptor size*/
        USB_DESC_TYPE_ENDPOINT, /*bDescriptorType:*/
        HID_EPIN_ADDR,          /*bEndpointAddress: Endpoint Address (IN)*/
        0x03,                   /*bmAttributes: Interrupt endpoint*/
        HID_EPIN_SIZE,          /*wMaxPacketSize: 4 Byte max */
        0x00,
        HID_BINTERVAL, /*bInterval: Polling Interval */

        0x07,                   /*bLength: Endpoint Descriptor size*/
        USB_DESC_TYPE_ENDPOINT, /*bDescriptorType:*/
        HID_EPOUT_ADDR,         /*bEndpointAddress: Endpoint Address (IN)*/
        0x03,                   /*bmAttributes: Interrupt endpoint*/
        HID_EPOUT_SIZE,         /*wMaxPacketSize: 4 Byte max */
        0x00,
        HID_BINTERVAL, /*bInterval: Polling Interval */

#if NUM_INTERFACES > 1

        /*     */
        /* CDC */
        /*     */
        // This "IAD" is needed for Windows since it ignores the standard Union Functional Descriptor
        0x08,                // bLength
        0x0B,                // IAD type
        CDC_MASTER_INTF_NUM, // First interface
        CDC_SLAVE_INTF_NUM,  // Next interface
        0x02,                // bInterfaceClass of the first interface
        0x02,                // bInterfaceSubClass of the first interface
        0x00,                // bInterfaceProtocol of the first interface
        0x00,                // Interface string index

        /*Interface Descriptor */
        0x09,                      /* bLength: Interface Descriptor size */
        USB_DESC_TYPE_INTERFACE,   /* bDescriptorType: Interface */
                                   /* Interface descriptor type */
        /*!*/ CDC_MASTER_INTF_NUM, /* bInterfaceNumber: Number of Interface */
        0x00,                      /* bAlternateSetting: Alternate setting */
        0x01,                      /* bNumEndpoints: 1 endpoint used */
        0x02,                      /* bInterfaceClass: Communication Interface Class */
        0x02,                      /* bInterfaceSubClass: Abstract Control Model */
        0x00,                      /* bInterfaceProtocol: Common AT commands */
        0x00,                      /* iInterface: */

        /*Header Functional Descriptor*/
        0x05, /* bLength: Endpoint Descriptor size */
        0x24, /* bDescriptorType: CS_INTERFACE */
        0x00, /* bDescriptorSubtype: Header Func Desc */
        0x10, /* bcdCDC: spec release number */
        0x01,

        /*Call Management Functional Descriptor*/
        0x05,                     /* bFunctionLength */
        0x24,                     /* bDescriptorType: CS_INTERFACE */
        0x01,                     /* bDescriptorSubtype: Call Management Func Desc */
        0x00,                     /* bmCapabilities: D0+D1 */
        /*!*/ CDC_SLAVE_INTF_NUM, /* bDataInterface: 0 */

        /*ACM Functional Descriptor*/
        0x04, /* bFunctionLength */
        0x24, /* bDescriptorType: CS_INTERFACE */
        0x02, /* bDescriptorSubtype: Abstract Control Management desc */
        0x02, /* bmCapabilities */

        /*Union Functional Descriptor*/
        0x05,                      /* bFunctionLength */
        0x24,                      /* bDescriptorType: CS_INTERFACE */
        0x06,                      /* bDescriptorSubtype: Union func desc */
        /*!*/ CDC_MASTER_INTF_NUM, /* bMasterInterface: Communication class interface */
        /*!*/ CDC_SLAVE_INTF_NUM,  /* bSlaveInterface0: Data Class Interface */

        /* Control Endpoint Descriptor*/
        0x07,                        /* bLength: Endpoint Descriptor size */
        USB_DESC_TYPE_ENDPOINT,      /* bDescriptorType: Endpoint */
        CDC_CMD_EP,                  /* bEndpointAddress */
        0x03,                        /* bmAttributes: Interrupt */
        LOBYTE(CDC_CMD_PACKET_SIZE), /* wMaxPacketSize: */
        HIBYTE(CDC_CMD_PACKET_SIZE),
        0x10, /* bInterval: */

        /* Interface descriptor */
        0x09,                    /* bLength */
        USB_DESC_TYPE_INTERFACE, /* bDescriptorType */
        CDC_SLAVE_INTF_NUM,      /* bInterfaceNumber */
        0x00,                    /* bAlternateSetting */
        0x02,                    /* bNumEndpoints */
        0x0A,                    /* bInterfaceClass: Communication class data */
        0x00,                    /* bInterfaceSubClass */
        0x00,                    /* bInterfaceProtocol */
        0x00,

        /*Endpoint OUT Descriptor*/
        0x07,                                /* bLength: Endpoint Descriptor size */
        USB_DESC_TYPE_ENDPOINT,              /* bDescriptorType: Endpoint */
        CDC_OUT_EP,                          /* bEndpointAddress */
        0x02,                                /* bmAttributes: Bulk */
        LOBYTE(CDC_DATA_FS_MAX_PACKET_SIZE), /* wMaxPacketSize: */
        HIBYTE(CDC_DATA_FS_MAX_PACKET_SIZE),
        0x00, /* bInterval: ignore for Bulk transfer */

        /*Endpoint IN Descriptor*/
        0x07,                                /* bLength: Endpoint Descriptor size */
        USB_DESC_TYPE_ENDPOINT,              /* bDescriptorType: Endpoint */
        CDC_IN_EP,                           /* bEndpointAddress */
        0x02,                                /* bmAttributes: Bulk */
        LOBYTE(CDC_DATA_FS_MAX_PACKET_SIZE), /* wMaxPacketSize: */
        HIBYTE(CDC_DATA_FS_MAX_PACKET_SIZE),
        0x00, /* bInterval: ignore for Bulk transfer */

        4, /* Descriptor size */
        3, /* Descriptor type */
        0x09,
        0x04,
#endif
};

USBD_ClassTypeDef USBD_Composite =
{
  USBD_Composite_Init,
  USBD_Composite_DeInit,
  USBD_Composite_Setup,
  NULL, //TODO
  USBD_Composite_EP0_RxReady,
  USBD_Composite_DataIn,
  USBD_Composite_DataOut,
  NULL, //TODO
  NULL, //TODO
  NULL, //TODO
  USBD_Composite_GetHSCfgDesc,
  USBD_Composite_GetFSCfgDesc,
  USBD_Composite_GetOtherSpeedCfgDesc,
  USBD_Composite_GetDeviceQualifierDescriptor,
};

static USBD_ClassTypeDef *USBD_Classes[MAX_CLASSES];

int in_endpoint_to_class[MAX_ENDPOINTS];

int out_endpoint_to_class[MAX_ENDPOINTS];

void USBD_Composite_Set_Classes(USBD_ClassTypeDef *hid_class, USBD_ClassTypeDef *cdc_class) {
    USBD_Classes[0] = hid_class;
    USBD_Classes[1] = cdc_class;
}

static USBD_ClassTypeDef * getClass(uint8_t index)
{
    switch(index)
    {
    case HID_INTF_NUM:
        return USBD_Classes[0];
    case CDC_MASTER_INTF_NUM:
    case CDC_SLAVE_INTF_NUM:
        return USBD_Classes[1];
    }
    return NULL;
}

static uint8_t USBD_Composite_Init (USBD_HandleTypeDef *pdev, uint8_t cfgidx) {
    int i;
    for(i = 0; i < NUM_CLASSES; i++) {
        if (USBD_Classes[i]->Init(pdev, cfgidx) != USBD_OK) {
            return USBD_FAIL;
        }
    }

    return USBD_OK;
}

static uint8_t  USBD_Composite_DeInit (USBD_HandleTypeDef *pdev, uint8_t cfgidx) {
    int i;
    for(i = 0; i < NUM_CLASSES; i++) {
        if (USBD_Classes[i]->DeInit(pdev, cfgidx) != USBD_OK) {
            return USBD_FAIL;
        }
    }

  return USBD_OK;
}

static uint8_t USBD_Composite_Setup (USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req) {
    int i;
    USBD_ClassTypeDef * device_class;
    device_class = getClass(req->wIndex);

    switch (req->bmRequest & USB_REQ_TYPE_MASK) {
        case USB_REQ_TYPE_CLASS :
            if (device_class != NULL)
                return device_class->Setup(pdev, req);
            else
                return USBD_FAIL;


        case USB_REQ_TYPE_STANDARD:
            switch (req->bRequest) {

                case USB_REQ_GET_DESCRIPTOR :
                    for(i = 0; i < NUM_CLASSES; i++) {
                        if (USBD_Classes[i]->Setup(pdev, req) != USBD_OK) {
                            return USBD_FAIL;
                        }
                    }

                break;

        case USB_REQ_GET_INTERFACE :
        case USB_REQ_SET_INTERFACE :
            if (device_class != NULL)
                return device_class->Setup(pdev, req);
            else
                return USBD_FAIL;
        }
    }
    return USBD_OK;
}

static uint8_t USBD_Composite_DataIn (USBD_HandleTypeDef *pdev, uint8_t epnum) {
    int i;

    i = in_endpoint_to_class[epnum];

    return USBD_Classes[i]->DataIn(pdev, epnum);
}

static uint8_t USBD_Composite_DataOut (USBD_HandleTypeDef *pdev, uint8_t epnum) {
  int i;

  i = out_endpoint_to_class[epnum];

  return USBD_Classes[i]->DataOut(pdev, epnum);

}

static uint8_t USBD_Composite_EP0_RxReady (USBD_HandleTypeDef *pdev) {
    int i;
    for(i = 0; i < NUM_CLASSES; i++) {
        if (USBD_Classes[i]->EP0_RxReady != NULL) {
            if (USBD_Classes[i]->EP0_RxReady(pdev) != USBD_OK) {
                return USBD_FAIL;
            }
        }
    }
    return USBD_OK;
}

static uint8_t  *USBD_Composite_GetFSCfgDesc (uint16_t *length) {
    *length = COMPOSITE_CDC_HID_DESCRIPTOR_SIZE;
    return COMPOSITE_CDC_HID_DESCRIPTOR;
}

static uint8_t  *USBD_Composite_GetHSCfgDesc (uint16_t *length) {
    *length = COMPOSITE_CDC_HID_DESCRIPTOR_SIZE;
    return COMPOSITE_CDC_HID_DESCRIPTOR;
}

static uint8_t  *USBD_Composite_GetOtherSpeedCfgDesc (uint16_t *length) {
    *length = COMPOSITE_CDC_HID_DESCRIPTOR_SIZE;
    return COMPOSITE_CDC_HID_DESCRIPTOR;
}

/* USB Standard Device Descriptor */
__ALIGN_BEGIN static uint8_t USBD_Composite_DeviceQualifierDesc[USB_LEN_DEV_QUALIFIER_DESC] __ALIGN_END =
{
  USB_LEN_DEV_QUALIFIER_DESC,
  USB_DESC_TYPE_DEVICE_QUALIFIER,
  0x00,
  0x02,
  0x00,
  0x00,
  0x00,
  0x40,
  0x01,
  0x00,
};

uint8_t  *USBD_Composite_GetDeviceQualifierDescriptor (uint16_t *length) {
  *length = sizeof (USBD_Composite_DeviceQualifierDesc);
  return USBD_Composite_DeviceQualifierDesc;
}
