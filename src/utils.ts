export function timeoutPromise<T>(promise: Promise<T>, timeout: number): Promise<T> {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error("Timeout"))
        }, timeout)
        promise.then((value) => {
            clearTimeout(timer)
            resolve(value)
        }).catch((error) => {
            clearTimeout(timer)
            reject(error)
        })
    })
}
