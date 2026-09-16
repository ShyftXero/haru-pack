# The tier choice, in the only terms that settle it: two real binaries and their real sizes.
# Embedded in docs/TIERS.md. The point is the trade, not the numbers — yours will differ with
# the interpreter and the dependency set, which is exactly why this shows a measurement rather
# than a table someone typed.
Output "docs/media/03-tiers.gif"
Set Shell "bash"
Set FontSize 20
Set Width 1150
Set Height 460
Set Padding 14
Set TypingSpeed 45ms
Set PlaybackSpeed 3
Hide
Type "export PS1='$ ' && cd $HARU_DEMO_ROOT/work && clear"
Enter
Show
Type "haru-pack hello.py -o hello-default"
Sleep 500ms
Enter
Sleep 40s
Type "haru-pack hello.py -o hello-thick --tier thick"
Sleep 500ms
Enter
Sleep 150s
Type "ls -lh hello-default hello-thick | awk '{print $5, $9}'"
Sleep 500ms
Enter
Sleep 5s
