package org.sonar.plugins.ldap.ldapreferralfilter; 

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DenyAllReferralFilterTest {

    DenyAllReferralFilter sut = new DenyAllReferralFilter();


    @Test
    public void testFollowReferral() throws Exception {
      String given="anyString";

      boolean returned = sut.followReferral(given);

      assertEquals(false, returned);
    } 
}
