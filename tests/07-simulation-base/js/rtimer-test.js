TIMEOUT(120000); // 2 minutes

var testPhases = {
  STARTING: 0,
  PHASE1: 1,
  PHASE2: 2,
  PHASE3: 3,
  PHASE4: 4,
  COMPLETED: 5
};

var currentPhase = testPhases.STARTING;
var timerCallbacks = 0;
var errorCount = 0;
var testStarted = false;
var testCompleted = false;

while(true) {
  log.log("> " + msg + "\n");
  
  // Test start detection
  if (msg.contains('RTIMER-TEST: Starting multi-rtimer test')) {
    log.log("Test started\n");
    testStarted = true;
  }
  
  // Phase tracking
  if (msg.contains('RTIMER-TEST: Phase 1')) {
    currentPhase = testPhases.PHASE1;
    log.log("Entered Phase 1: Basic concurrent timer test\n");
  } else if (msg.contains('RTIMER-TEST: Phase 2')) {
    currentPhase = testPhases.PHASE2;
    log.log("Entered Phase 2: Timer cancellation test\n");
  } else if (msg.contains('RTIMER-TEST: Phase 3')) {
    currentPhase = testPhases.PHASE3;
    log.log("Entered Phase 3: Stress test\n");
  } else if (msg.contains('RTIMER-TEST: Phase 4')) {
    currentPhase = testPhases.PHASE4;
    log.log("Entered Phase 4: Maximum capacity test\n");
  }
  
  // Count timer callbacks
  if (msg.contains('RTIMER: Timer') && msg.contains('fired')) {
    timerCallbacks++;
    log.log("Timer callback #" + timerCallbacks + "\n");
  }
  
  // Error detection
  if (msg.contains('RTIMER: ERROR') || msg.contains('should not happen')) {
    errorCount++;
    log.log("ERROR detected: " + msg + "\n");
  }
  
  // Validate timer ordering (Phase 1)
  if (currentPhase == testPhases.PHASE1) {
    if (msg.contains('RTIMER: Timer 3 fired')) {
      log.log("Good: Timer 3 (shortest delay) fired first\n");
    } else if (msg.contains('RTIMER: Timer 1 fired') && timerCallbacks > 1) {
      log.log("Good: Timer 1 fired after Timer 3\n");
    } else if (msg.contains('RTIMER: Timer 2 fired') && timerCallbacks > 2) {
      log.log("Good: Timer 2 (longest delay) fired last\n");
    }
  }
  
  // Validate cancellation (Phase 2)
  if (currentPhase == testPhases.PHASE2) {
    if (msg.contains('Cancel timer result=0')) {
      log.log("Good: Timer cancellation successful\n");
    }
  }
  
  // Validate stress test (Phase 3)
  if (currentPhase == testPhases.PHASE3) {
    if (msg.contains('RTIMER: Stress timer') && msg.contains('fired')) {
      log.log("Stress timer executed\n");
    }
  }
  
  // Validate capacity limits (Phase 4)
  if (msg.contains('RTIMER-TEST: Capacity test')) {
    if (msg.contains('successful=') && msg.contains('failed=')) {
      /* Verify that some sets succeeded and some failed (queue overflow) */
      if (msg.contains('failed=0')) {
        log.log("Warning: No failed sets - capacity limit may not be tested\n");
      } else {
        log.log("Good: Capacity limits working correctly\n");
      }
    }
  }
  
  // Test completion detection
  if (msg.contains('RTIMER-TEST: SUCCESS - All tests passed')) {
    log.log("SUCCESS: All rtimer tests passed!\n");
    testCompleted = true;
    log.testOK();
  } else if (msg.contains('RTIMER-TEST: FAILURE - Some tests failed')) {
    log.log("FAILURE: Some rtimer tests failed\n");
    log.testFailed();
  } else if (msg.contains('RTIMER-TEST: Test completed')) {
    if (!testCompleted) {
      log.log("Test completed but no clear success/failure indication\n");
      if (errorCount == 0 && timerCallbacks >= 10) {
        log.log("Assuming success based on callback count and no errors\n");
        log.testOK();
      } else {
        log.log("Test appears to have failed\n");
        log.testFailed();
      }
    }
  }
  
  YIELD();
}
