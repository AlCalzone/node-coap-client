"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function createDeferredPromise() {
    let res;
    let rej;
    const promise = new Promise((resolve, reject) => {
        res = resolve;
        rej = reject;
    });
    promise.resolve = res;
    promise.reject = rej;
    return promise;
}
exports.createDeferredPromise = createDeferredPromise;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiRGVmZXJyZWRQcm9taXNlLmpzIiwic291cmNlUm9vdCI6IkM6L1VzZXJzL0RvbWluaWMvRG9jdW1lbnRzL1Zpc3VhbCBTdHVkaW8gMjAxNy9SZXBvc2l0b3JpZXMvbm9kZS1jb2FwLWNsaWVudC9zcmMvIiwic291cmNlcyI6WyJsaWIvRGVmZXJyZWRQcm9taXNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBS0E7SUFDQyxJQUFJLEdBQXlDLENBQUM7SUFDOUMsSUFBSSxHQUEyQixDQUFDO0lBRWhDLE1BQU0sT0FBTyxHQUFHLElBQUksT0FBTyxDQUFJLENBQUMsT0FBTyxFQUFFLE1BQU0sRUFBRSxFQUFFO1FBQ2xELEdBQUcsR0FBRyxPQUFPLENBQUM7UUFDZCxHQUFHLEdBQUcsTUFBTSxDQUFDO0lBQ2QsQ0FBQyxDQUF1QixDQUFDO0lBRXpCLE9BQU8sQ0FBQyxPQUFPLEdBQUcsR0FBRyxDQUFDO0lBQ3RCLE9BQU8sQ0FBQyxNQUFNLEdBQUcsR0FBRyxDQUFDO0lBRXJCLE1BQU0sQ0FBQyxPQUFPLENBQUM7QUFDaEIsQ0FBQztBQWJELHNEQWFDIn0=