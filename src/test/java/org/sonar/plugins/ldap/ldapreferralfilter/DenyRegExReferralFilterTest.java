package org.sonar.plugins.ldap.ldapreferralfilter;

import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class DenyRegExReferralFilterTest {

  DenyRegExReferralFilter sut;
  private List<String> deniedReferrals;

  @Before
  public void setUp() throws Exception {
    deniedReferrals = new ArrayList<>();
  }

  @Test
  public void testBlockReferralsContainingString() throws Exception {
    String containingString = "Block";
    deniedReferrals.add(".*" + containingString + ".*");
    sut = new DenyRegExReferralFilter(deniedReferrals);

    boolean thisShouldBeBlocked = sut.followReferral("ThisShouldBeBlocked");
    assertEquals(false, thisShouldBeBlocked);
    thisShouldBeBlocked = sut.followReferral("BlockedShouldItBe");
    assertEquals(false, thisShouldBeBlocked);
    thisShouldBeBlocked = sut.followReferral("itshouldBlockThisString");
    assertEquals(false, thisShouldBeBlocked);

    boolean thisShouldNotBeBlocked=sut.followReferral("thisShouldBeAllowed");
    assertEquals(true, thisShouldNotBeBlocked);
  }
}
