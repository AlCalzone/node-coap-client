"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function createDeferredPromise() {
    var res;
    var rej;
    var promise = new Promise(function (resolve, reject) {
        res = resolve;
        rej = reject;
    });
    promise.resolve = res;
    promise.reject = rej;
    return promise;
}
exports.createDeferredPromise = createDeferredPromise;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiRGVmZXJyZWRQcm9taXNlLmpzIiwic291cmNlUm9vdCI6IkM6L1VzZXJzL0RvbWluaWMvRG9jdW1lbnRzL1Zpc3VhbCBTdHVkaW8gMjAxNy9SZXBvc2l0b3JpZXMvbm9kZS1jb2FwLWNsaWVudC9zcmMvIiwic291cmNlcyI6WyJsaWIvRGVmZXJyZWRQcm9taXNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBS0E7SUFDQyxJQUFJLEdBQXlDLENBQUM7SUFDOUMsSUFBSSxHQUEyQixDQUFDO0lBRWhDLElBQU0sT0FBTyxHQUFHLElBQUksT0FBTyxDQUFJLFVBQUMsT0FBTyxFQUFFLE1BQU07UUFDOUMsR0FBRyxHQUFHLE9BQU8sQ0FBQztRQUNkLEdBQUcsR0FBRyxNQUFNLENBQUM7SUFDZCxDQUFDLENBQXVCLENBQUM7SUFFekIsT0FBTyxDQUFDLE9BQU8sR0FBRyxHQUFHLENBQUM7SUFDdEIsT0FBTyxDQUFDLE1BQU0sR0FBRyxHQUFHLENBQUM7SUFFckIsTUFBTSxDQUFDLE9BQU8sQ0FBQztBQUNoQixDQUFDO0FBYkQsc0RBYUMifQ==