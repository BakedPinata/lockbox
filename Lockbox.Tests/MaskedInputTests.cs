using Lockbox.Cli;

namespace Lockbox.Tests;

[TestClass]
public sealed class MaskedInputTests
{
    private static ConsoleKeyInfo Char(char c) => new(c, ConsoleKey.A, shift: false, alt: false, control: false);

    private static ConsoleKeyInfo Key(ConsoleKey key, char c = '\0') => new(c, key, shift: false, alt: false, control: false);

    private static (string? Value, string Echo) Read(params ConsoleKeyInfo[] keys)
    {
        var queue = new Queue<ConsoleKeyInfo>(keys);
        var echo = new StringWriter();
        var value = MaskedInput.Read(queue.Dequeue, echo);
        return (value, echo.ToString());
    }

    [TestMethod]
    public void EchoesAStarPerCharacter()
    {
        var (value, echo) = Read(Char('a'), Char('b'), Char('c'), Key(ConsoleKey.Enter, '\r'));

        Assert.AreEqual("abc", value);
        Assert.AreEqual("***" + Environment.NewLine, echo);
    }

    [TestMethod]
    public void BackspaceDeletes()
    {
        var (value, echo) = Read(Char('a'), Char('b'), Key(ConsoleKey.Backspace, '\b'), Char('c'), Key(ConsoleKey.Enter, '\r'));

        Assert.AreEqual("ac", value);
        Assert.AreEqual("**\b \b*" + Environment.NewLine, echo);
    }

    [TestMethod]
    public void BackspaceOnEmptyInputDoesNothing()
    {
        var (value, echo) = Read(Key(ConsoleKey.Backspace, '\b'), Char('a'), Key(ConsoleKey.Enter, '\r'));

        Assert.AreEqual("a", value);
        Assert.AreEqual("*" + Environment.NewLine, echo);
    }

    [TestMethod]
    public void EscapeCancels()
    {
        var (value, _) = Read(Char('a'), Key(ConsoleKey.Escape, '\u001b'));

        Assert.IsNull(value);
    }

    [TestMethod]
    public void EnterWithNothingTypedReturnsEmpty()
    {
        Assert.AreEqual("", Read(Key(ConsoleKey.Enter, '\r')).Value);
    }

    [TestMethod]
    public void ControlAndNavigationKeysAreIgnored()
    {
        var (value, echo) = Read(
            Char('a'),
            Key(ConsoleKey.Tab, '\t'),
            Key(ConsoleKey.LeftArrow),
            Key(ConsoleKey.F5),
            Char('b'),
            Key(ConsoleKey.Enter, '\r'));

        Assert.AreEqual("ab", value);
        Assert.AreEqual("**" + Environment.NewLine, echo);
    }

    [TestMethod]
    public void SurrogatePairsEchoOnceAndDeleteTogether()
    {
        const string emoji = "😀";
        var (value, echo) = Read(
            Char('a'),
            Char(emoji[0]),
            Char(emoji[1]),
            Char('b'),
            Key(ConsoleKey.Backspace, '\b'),
            Key(ConsoleKey.Backspace, '\b'),
            Char(emoji[0]),
            Char(emoji[1]),
            Key(ConsoleKey.Enter, '\r'));

        Assert.AreEqual("a" + emoji, value);
        Assert.AreEqual("***\b \b\b \b*" + Environment.NewLine, echo);
    }
}
