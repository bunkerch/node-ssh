const MAX_CHANNEL_IDENTIFIER = 0xffff_ffff

interface ChannelIdentifierOwner {
    localChannelIndex: number
    readonly channels: ReadonlyMap<number, unknown>
}

/** Allocate an unused RFC 4254 uint32 channel number and advance the owner's cursor. */
export default function allocateChannelIdentifier(owner: ChannelIdentifierOwner): number {
    let identifier = owner.localChannelIndex >>> 0
    for (let attempts = 0; attempts <= owner.channels.size; attempts++) {
        owner.localChannelIndex = identifier === MAX_CHANNEL_IDENTIFIER ? 0 : identifier + 1
        if (!owner.channels.has(identifier)) return identifier
        identifier = owner.localChannelIndex
    }
    throw new Error("No SSH channel identifiers are available")
}
