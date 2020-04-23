#ifndef _CRUST_VALIDATE_STATUS_H_
#define _CRUST_VALIDATE_STATUS_H_

typedef enum _validation_status_t
{
    VALIDATE_STOP = 0,
    VALIDATE_WAITING = 1,
    VALIDATE_MEANINGFUL = 2,
    VALIDATE_EMPTY = 3
} validation_status_t;

#endif /* !_CRUST_VALIDATE_STATUS_H_ */
