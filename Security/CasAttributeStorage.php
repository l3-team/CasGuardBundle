<?php

namespace L3\Bundle\CasGuardBundle\Security;

class CasAttributeStorage
{
    private array $attributes = [];

    public function setAttributes(array $attributes): void
    {
        $this->attributes = $attributes;
    }

    public function getAttributes(): array
    {
        return $this->attributes;
    }
}
