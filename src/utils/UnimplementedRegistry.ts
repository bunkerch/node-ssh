interface Registration {
    readonly reject: () => void
}

const registrations = new WeakMap<object, Map<number, Registration[]>>()

export function registerUnimplementedRejection(
    owner: object,
    sequenceNumber: number,
    reject: () => void,
): () => void {
    let bySequence = registrations.get(owner)
    if (!bySequence) {
        bySequence = new Map()
        registrations.set(owner, bySequence)
    }
    let matching = bySequence.get(sequenceNumber)
    if (!matching) {
        matching = []
        bySequence.set(sequenceNumber, matching)
    }
    const registration = { reject }
    matching.push(registration)

    return () => {
        const current = registrations.get(owner)?.get(sequenceNumber)
        if (!current) return
        const index = current.indexOf(registration)
        if (index !== -1) current.splice(index, 1)
        if (current.length === 0) {
            const ownerRegistrations = registrations.get(owner)
            ownerRegistrations?.delete(sequenceNumber)
            if (ownerRegistrations?.size === 0) registrations.delete(owner)
        }
    }
}

export function rejectUnimplementedPacket(owner: object, sequenceNumber: number): boolean {
    const bySequence = registrations.get(owner)
    const matching = bySequence?.get(sequenceNumber)
    const registration = matching?.shift()
    if (!registration || !matching || !bySequence) return false
    if (matching.length === 0) bySequence.delete(sequenceNumber)
    if (bySequence.size === 0) registrations.delete(owner)
    registration.reject()
    return true
}

export function unimplementedPacketError(sequenceNumber: number, operation: string): Error {
    return new Error(
        `SSH peer did not implement ${operation} (outbound packet sequence ${sequenceNumber})`,
    )
}
