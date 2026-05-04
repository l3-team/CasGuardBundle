<?php

namespace L3\Bundle\CasGuardBundle\Entity;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * this is a very basic implementation exemple, use your own "CasUser" or extends this class
 */
class CasUser implements CasUserInterface, UserInterface
{
    private string $identifier;

    private array $roles = [];

    private $attributes = [];

    public function __construct(string $identifier)
    {
        $this->identifier = $identifier;
    }

    public function setCasAttributes(array $attributes)
    {
        $this->attributes = $attributes;
    }

    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * @see UserInterface
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        // guarantee every user at least has ROLE_USER
        $roles[] = 'ROLE_USER';

        return array_unique($roles);
    }

    /**
     * @param list<string> $roles
     */
    public function setRoles(array $roles): static
    {
        $this->roles = $roles;

        return $this;
    }

    /**
     * @return non-empty-string
     */
    public function getUserIdentifier(): string
    {
        return $this->identifier;
    }
}
