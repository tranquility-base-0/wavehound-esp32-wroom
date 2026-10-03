Import("env")

lf = [f for f in env["LINKFLAGS"] if f != "-fno-lto"]
env.Replace(LINKFLAGS=lf + ["-flto"])

print("[lto_link] final LINKFLAGS tail:", env["LINKFLAGS"][-6:])
