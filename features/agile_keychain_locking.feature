Feature: Lock and Unlock a keychain
  So that I can control access to my keychain
  As an API user
  I want to be able to lock and unlock my keychain at will

Scenario: Unlocking a keychain
  Given I have a locked keychain
  When I unlock it
  Then it will become unlocked
  And I will be able to see its contents

Scenario: Locking a keychain
  Given I have an unlocked keychain
  When I lock the keychain
  Then it will become locked
