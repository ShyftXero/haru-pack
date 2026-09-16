# Where your code thinks it lives once it is inside a binary.
#
# This is the question every packaging tool gets asked, and the reason the answer matters is
# that `__file__` and the working directory stop agreeing the moment the code is staged. The
# recording shows both, plus the variable that resolves it, so the README does not have to ask
# anyone to take its word.
Output "docs/media/04-run-in-place.gif"
Set Shell "bash"
Set FontSize 19
Set Width 1200
Set Height 420
Set Padding 14
Set TypingSpeed 45ms
Set PlaybackSpeed 2.5
Hide
Type "export PS1='$ ' && cd $HARU_DEMO_ROOT/work && clear"
Enter
Show
Type "cat whereami.py"
Sleep 400ms
Enter
Sleep 2s
Type "haru-pack whereami.py"
Sleep 500ms
Enter
Sleep 40s
Type "./whereami"
Sleep 400ms
Enter
Sleep 7s
