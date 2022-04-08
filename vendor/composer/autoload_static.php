<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit97b02e227cfe13cc94392396a29de38d
{
    public static $prefixLengthsPsr4 = array (
        'S' => 
        array (
            'Sam\\JwtBlogPost\\' => 16,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Sam\\JwtBlogPost\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit97b02e227cfe13cc94392396a29de38d::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit97b02e227cfe13cc94392396a29de38d::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit97b02e227cfe13cc94392396a29de38d::$classMap;

        }, null, ClassLoader::class);
    }
}