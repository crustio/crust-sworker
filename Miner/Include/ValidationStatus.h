#ifndef _CRUST_VALIDATE_STATUS_H_
#define _CRUST_VALIDATE_STATUS_H_

#define VALIDATE_MK_ERROR(x) (0x00000000 | (x))

enum ValidationStatus
{
    ValidateStop = 0,
    ValidateWaiting = 1,
    ValidateMeaningful = 2,
    ValidateEmpty = 3
};

typedef enum _validate_status_t
{
    VALIDATION_REPORT_SIGN_SUCCESS = VALIDATE_MK_ERROR(0),
    VALIDATION_REPORT_SIGN_FAILED = VALIDATE_MK_ERROR(400),
} validate_status_t;

#endif /* !_CRUST_VALIDATE_STATUS_H_ */
