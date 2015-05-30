package org.sonar.plugins.ldap.ldapreferralfilter; 

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AllowAllReferralFilterTest {

    AllowAllReferralFilter sut = new AllowAllReferralFilter();

    @Test
    public void testFollowReferral() throws Exception {
      String given="anyString";

      boolean returned = sut.followReferral(given);

      assertEquals(true, returned);
    } 
}
