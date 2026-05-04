<?php

namespace L3\Bundle\CasGuardBundle\Security;

use L3\Bundle\CasGuardBundle\Entity\CasUser;
use L3\Bundle\CasGuardBundle\Entity\CasUserInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;


/**
 * this is a very basic implementation exemple, use your own "CasUserProvider" or extends this class
 */
class CasUserProvider implements UserProviderInterface
{

    public function __construct(
        private CasAttributeStorage $casAttributeStorage
    ) {
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        $attributes = $this->casAttributeStorage->getAttributes();

        $user = new CasUser($identifier);
        if ($user instanceof CasUserInterface) {
            $user->setCasAttributes($attributes);

            $roles = ['ROLE_USER'];
            if (isset($attributes['memberOf']) && in_array('admin', $attributes['memberOf'])) {
                $role[] = 'ROLE_AMIN';
            }
            $user->setRoles($roles);
        }

        if (is_null($user)) {
            throw new UserNotFoundException('Utilisateur introuvable ou desactivé !');
        }

        return $user;
    }

    /**
     * Refreshes the user after being reloaded from the session.
     *
     * @return UserInterface
     */
    public function refreshUser(UserInterface $user): UserInterface
    {
        return $user;
    }

    public function supportsClass(string $class): bool
    {
        return is_subclass_of($class, UserInterface::class) || is_subclass_of($class, CasUserInterface::class);
    }
}
