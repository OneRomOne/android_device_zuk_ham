/*
 * Copyright (C) 2015 Cyanogen, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define LOG_TAG "FingerprintHal"

#include <errno.h>
#include <string.h>
#include <cutils/log.h>
#include <utils/Thread.h>
#include <hardware/hardware.h>
#include <hardware/fingerprint.h>

#include "fpd_sm.h"
#include "fpd_client.h"

typedef struct {
    fingerprint_device_t device;
    android::Mutex notify_lock;
    uint64_t operation_id;
    uint32_t gid;
    uint64_t challenge;
} fpc1020_device_t;

static fpd_sm_t *g_fpd_sm;

static fingerprint_notify_t fingerprint_get_notify(struct fingerprint_device *dev)
{
    fpc1020_device_t *fpc1020_dev = (fpc1020_device_t *) dev;
    android::Mutex::Autolock l(fpc1020_dev->notify_lock);
    return dev->notify;
}

static uint64_t get_64bit_rand() {
    return (((uint64_t)rand()) << 32) | ((uint64_t)rand());
}

static int fingerprint_close(hw_device_t *dev)
{
    if (dev) {
        if (g_fpd_sm != NULL) {
            fpd_sm_destroy(g_fpd_sm);
            g_fpd_sm = NULL;
        }
        free(dev);
        return 0;
    } else {
        return -1;
    }
}

static inline int fpd_result_to_hal(int result) {
    return result == FPD_SM_OK ? 0 : FINGERPRINT_ERROR;
}

static int fingerprint_authenticate(struct fingerprint_device *dev,
                                    uint64_t operation_id,
                                    uint32_t gid) {
    fpc1020_device_t *device = (fpc1020_device_t *)dev;

    ALOGI("fingerprint_authenticate");
    int ret = fpd_result_to_hal(fpd_sm_start_authenticating(g_fpd_sm));
    if (ret != 0) {
        ALOGE("Starting authentication mode failed: %d", ret);
        return ret;
    }

    device->operation_id = operation_id;
    device->gid = gid;

    return 0;
}

static uint64_t fingerprint_pre_enroll(struct fingerprint_device *dev) {
    ALOGI("fingerprint_pre_enroll");
    fpc1020_device_t *device = (fpc1020_device_t *) dev;
    device->challenge = get_64bit_rand();
    return device->challenge;
}

static int fingerprint_post_enroll(struct fingerprint_device *dev) {
    ALOGI("fingerprint_post_enroll");
    fpc1020_device_t *device = (fpc1020_device_t *) dev;
    device->challenge = 0;
    return 0;
}

static int fingerprint_enroll(struct fingerprint_device *dev,
                              const hw_auth_token_t *hat,
                              uint32_t gid,
                              uint32_t timeout_sec) {
    ALOGI("fingerprint_enroll, timeout %d, group %d", timeout_sec, gid);

    fpc1020_device_t *device = (fpc1020_device_t *)dev;
    if (!hat) {
        ALOGW("Null auth token");
        return -EINVAL;
    }

    if (hat->version != HW_AUTH_TOKEN_VERSION) {
        ALOGW("Invalid HW_AUTH_TOKEN_VERSION");
        return -EPROTONOSUPPORT;
    }
    if (hat->challenge != device->challenge && (hat->authenticator_type & HW_AUTH_FINGERPRINT)) {
        ALOGW("Failed to pass enroll challenge");
        return -EPERM;
    }

    int ret = fpd_result_to_hal(fpd_sm_start_enrolling(g_fpd_sm, timeout_sec));
    if (ret != 0) {
        ALOGE("Starting enrollment mode failed: %d", ret);
    }

    return ret;
}

static uint64_t fingerprint_get_auth_id(struct fingerprint_device *dev)
{
    ALOGI("fingerprint_get_auth_id");

    fpd_enrolled_ids_t enrolled;
    if (fpd_sm_get_enrolled_ids(g_fpd_sm, &enrolled) != FPD_SM_OK) {
        ALOGI("Failed to get number of enrolled fingerprints");
        return 0;
    }

    // it's cheap, I know... but until we implement groups this will do.
    ALOGI("Returning fingerprint count (%d) as authentication id", enrolled.id_num);
    return enrolled.id_num;
}

static int fingerprint_set_active_group(struct fingerprint_device *dev,
                                        uint32_t gid,
                                        const char * __unused path)
{
    ALOGI("Set active fingerprint group to %d", gid);
    fpc1020_device_t *device = (fpc1020_device_t *) dev;
    device->gid = gid;
    return 0;
}

static int fingerprint_enumerate(struct fingerprint_device *dev,
                                 fingerprint_finger_id_t *results,
                                 uint32_t *max_size)
{
    ALOGI("fingerprint_enumerate");

    fpc1020_device_t *device = (fpc1020_device_t *)dev;

    fpd_enrolled_ids_t enrolled;
    if (fpd_sm_get_enrolled_ids(g_fpd_sm, &enrolled) != FPD_SM_OK) {
        return FINGERPRINT_ERROR;
    }

    if (*max_size == 0) {
        *max_size = enrolled.id_num;
        ALOGI("Returning number of fingerprints: %d", enrolled.id_num);
    } else {
        for (size_t i = 0; i < *max_size && i < enrolled.id_num; i++) {
            results[i].fid = enrolled.ids[i];
            results[i].gid = device->gid;
        }
        ALOGI("Returning fingerprint ids for %d fingerprints", enrolled.id_num);
    }

    return 0;
}

static int fingerprint_cancel(struct fingerprint_device __unused *dev) {
    ALOGI("fingerprint_cancel");
    fpd_sm_cancel_authentication(g_fpd_sm);
    fpd_sm_cancel_enrollment(g_fpd_sm);
    return 0;
}

static int fingerprint_remove(struct fingerprint_device *dev,
                              uint32_t gid,
                              uint32_t fid) {
    ALOGI("fingerprint_remove, id 0x%08x gid 0x%08x", fid, gid);
    fpc1020_device_t *device = (fpc1020_device_t *)dev;
    if (device->gid != gid) {
        ALOGW("Invalid gid");
        return -EINVAL;
    }

    int ret = fpd_result_to_hal(fpd_sm_remove_id(g_fpd_sm, fid));
    if (ret != 0) {
        ALOGE("Removing enrolled fingerprint failed: %d", ret);
        return ret;
    }

    fingerprint_notify_t notify = fingerprint_get_notify(dev);
    if (notify) {
        fingerprint_msg_t msg;
        msg.type = FINGERPRINT_TEMPLATE_REMOVED;
        msg.data.removed.finger.fid = fid;
        msg.data.removed.finger.gid = gid;
        notify(&msg);
    }

    return 0;
}

static int set_notify_callback(struct fingerprint_device *dev,
                                fingerprint_notify_t notify) {
    ALOGI("set_notify_callback");

    fpc1020_device_t *fpc1020_dev = (fpc1020_device_t *)dev;
    android::Mutex::Autolock l(fpc1020_dev->notify_lock);
    dev->notify = notify;

    fpd_sm_set_notify(g_fpd_sm, notify);

    return 0;
}

static int fingerprint_open(const hw_module_t* module, const char __unused *id,
                            hw_device_t** device)
{
    if (device == NULL) {
        ALOGE("NULL device on open");
        return -EINVAL;
    }

    fpc1020_device_t *dev = malloc(sizeof(fpc1020_device_t));
    if (dev == NULL) {
        return -ENOMEM;
    }
    memset(dev, 0, sizeof(fpc1020_device_t));

    dev->device.common.tag = HARDWARE_DEVICE_TAG;
    dev->device.common.version = HARDWARE_MODULE_API_VERSION(2, 0);
    dev->device.common.module = (struct hw_module_t*) module;
    dev->device.common.close = fingerprint_close;

    dev->device.authenticate = fingerprint_authenticate;
    dev->device.cancel = fingerprint_cancel;

    // new in 2.0 api
    dev->device.pre_enroll = fingerprint_pre_enroll;

    dev->device.enroll = fingerprint_enroll;

    // new in 2.0 api
    dev->device.post_enroll = fingerprint_post_enroll;
    dev->device.get_authenticator_id = fingerprint_get_auth_id;
    dev->device.set_active_group = fingerprint_set_active_group;
    dev->device.enumerate = fingerprint_enumerate;

    dev->device.remove = fingerprint_remove;
    dev->device.set_notify = set_notify_callback;
    dev->device.notify = NULL;

    // no longer exists in 2.0 api
    //dev->get_enrollment_info = fingerprint_get_enrollment_info;
    //dev->release_enrollment_info = fingerprint_release_enrollment_info;
    //dev->get_num_enrollment_steps = fingerprint_get_num_enrollment_steps;

    if ((g_fpd_sm = fpd_sm_init()) == NULL) {
        free(dev);
        return -ENODEV;
    }

    dev->gid = 0;
    dev->operation_id = 0;
    dev->challenge = get_64bit_rand();

    *device = (hw_device_t*)&dev->device;
    return 0;
}

static struct hw_module_methods_t fingerprint_module_methods = {
    .open = fingerprint_open,
};

fingerprint_module_t HAL_MODULE_INFO_SYM = {
    .common = {
        .tag                = HARDWARE_MODULE_TAG,
        .module_api_version = FINGERPRINT_MODULE_API_VERSION_2_0,
        .hal_api_version    = HARDWARE_HAL_API_VERSION,
        .id                 = FINGERPRINT_HARDWARE_MODULE_ID,
        .name               = "Ham Fingerprint HAL",
        .author             = "Cyanogen, Inc",
        .methods            = &fingerprint_module_methods,
        .dso                = NULL,
        .reserved           = { 0 }
    },
};
