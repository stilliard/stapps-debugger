<?php

namespace Tests\Functional;

class SPFpageTest extends BaseTestCase
{
    /**
     * Test that the spf route loads the spf debugger
     */
    public function testGetSPF()
    {
        $response = $this->runApp('GET', '/spf');

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertContains('SPF Debugger', (string)$response->getBody());
    }

    /**
     * Test sending SPF data
     */
    public function testPostSPF()
    {
        $response = $this->runApp('POST', '/spf', [
            'email' => 'demo@missionresources.co.uk',
            'ip' => '5.153.230.21',
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertContains('SPF Validation Results', (string)$response->getBody());
    }

}
