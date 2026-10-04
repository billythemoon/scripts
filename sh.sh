find / -type f 2>/dev/null -exec python3 -c "import hashlib, sys; [print(f) for f in sys.argv[1:] if hashlib.md5(open(f,'rb').read()).hexdigest().endswith('c5ef')]" {} +
