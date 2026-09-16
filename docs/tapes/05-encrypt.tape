# Encryption, and the honest shape of it: the right secret runs, the wrong one does not.
#
# Embedded in docs/ENCRYPTION_LICENSING.md, next to the paragraph explaining what this does
# NOT stop. The recording proves the mechanism works; it cannot prove a licensee who owns the
# machine cannot get in, and the surrounding prose is what says so.
#
# The passphrase is a throwaway, and it is on screen on purpose: the `export` is typed while
# hidden but stays in the scrollback, so the reader can see what DEMO_SECRET holds. It is
# passed with `--secret-env` rather than `--secret` — argv is world-readable in `ps`, which is
# a documented sharp edge, and a recording that modelled the bad habit would teach it. Do not
# replace this with a real secret to "make it realistic"; the GIF is published.
Output "docs/media/05-encrypt.gif"
Set Shell "bash"
Set FontSize 19
Set Width 1200
Set Height 500
Set Padding 14
Set TypingSpeed 45ms
Set PlaybackSpeed 3
Hide
Type "export PS1='$ ' && cd $HARU_DEMO_ROOT/work && clear"
Enter
Type "export DEMO_SECRET=demo-passphrase-not-a-real-one"
Enter
Show
Type "haru-pack hello.py -o locked --encrypt --secret-env DEMO_SECRET"
Sleep 500ms
Enter
Sleep 45s
Type "HARU_SECRET=$DEMO_SECRET ./locked"
Sleep 500ms
Enter
Sleep 8s
Type "HARU_SECRET=wrong-passphrase ./locked"
Sleep 500ms
Enter
Sleep 8s
