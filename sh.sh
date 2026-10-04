find / -user susan -perm 777 -type f 2>/dev/null | xargs -I {} sh -c 'lsattr "{}" 2>/dev/null' | grep '\-i\-'
