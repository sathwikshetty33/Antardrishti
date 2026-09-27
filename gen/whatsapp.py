"""chat (replay): whatsapp captures from the dedicated test phone (pcapdroid),
dropped by the user into dataset/external/whatsapp. never synthesized."""
import replay


def start(duration, seed, ctx):
    return replay.start(duration, seed, ctx, "whatsapp")
