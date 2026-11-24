namespace Lockbox.Tests;

[TestClass]
public sealed class AccountInfoTests
{
    [TestMethod]
    public void SameSidIsTheSameAccountEvenIfRenamed()
    {
        var renamed = Accounts.Owner with { Account = @"CONTOSO\alice.smith" };

        Assert.IsTrue(Accounts.Owner.IsSameAccountAs(renamed));
    }

    [TestMethod]
    public void DifferentSidIsADifferentAccountEvenWithTheSameName()
    {
        var recreated = Accounts.Owner with { Sid = "S-1-5-21-1000-9999" };

        Assert.IsFalse(Accounts.Owner.IsSameAccountAs(recreated));
    }

    [TestMethod]
    public void WithoutASidAccountNamesAreComparedIgnoringCase()
    {
        var noSid = new AccountInfo(@"contoso\ALICE", null, "PC01");

        Assert.IsTrue(Accounts.Owner.IsSameAccountAs(noSid));
        Assert.IsTrue(noSid.IsSameAccountAs(Accounts.Owner));
        Assert.IsFalse(noSid.IsSameAccountAs(Accounts.Other));
    }

    [TestMethod]
    public void MachineIsNotPartOfAccountIdentity()
    {
        Assert.IsTrue(Accounts.Owner.IsSameAccountAs(Accounts.OwnerElsewhere));
        Assert.IsFalse(Accounts.Owner.IsSameMachineAs(Accounts.OwnerElsewhere));
        Assert.IsTrue(Accounts.Owner.IsSameMachineAs(Accounts.Owner with { Machine = "pc01" }));
    }

    [TestMethod]
    public void ToStringShowsAccountAndMachine() =>
        Assert.AreEqual(@"CONTOSO\alice on PC01", Accounts.Owner.ToString());

    [TestMethod]
    public void GetCurrentDescribesThisProcess()
    {
        var current = AccountInfo.GetCurrent();

        Assert.AreEqual(Environment.MachineName, current.Machine);
        Assert.EndsWith(Environment.UserName, current.Account, StringComparison.OrdinalIgnoreCase);
        Assert.AreEqual(OperatingSystem.IsWindows(), current.Sid is not null);
    }
}
