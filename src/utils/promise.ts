export function makePromise<T>(): [Promise<T>, (value: T) => void, (error: Error) => void] {
    let resolve: (value: T) => void
    let reject: (error: Error) => void
    const promise = new Promise<T>((res, rej) => {
        resolve = res
        reject = rej
    })
    return [promise, resolve!, reject!]
}
