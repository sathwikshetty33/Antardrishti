"""replay of public non-vpn pcaps (iscx / vnat) from dataset/external/public (p2)."""
import replay


def start(duration, seed, ctx):
    return replay.start(duration, seed, ctx, "public")
