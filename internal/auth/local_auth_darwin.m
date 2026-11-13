//go:build darwin && cgo

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>

int envh_local_auth_can_evaluate(void) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        BOOL available = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error];
        return available ? 0 : (int)(error ? error.code : -1);
    }
}

int envh_local_auth_evaluate(void) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *availabilityError = nil;
        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&availabilityError]) {
            return (int)(availabilityError ? availabilityError.code : -1);
        }

        dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
        __block BOOL succeeded = NO;
        __block NSInteger errorCode = -1;
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:@"Unlock this env-host project environment"
                          reply:^(BOOL success, NSError *error) {
            succeeded = success;
            errorCode = success ? 0 : (error ? error.code : -1);
            dispatch_semaphore_signal(semaphore);
        }];
        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
        return succeeded ? 0 : (int)errorCode;
    }
}
