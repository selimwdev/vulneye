<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="csrf-token" content="{{ csrf_token() }}">

        <title>{{ config('app.name', 'Laravel') }}</title>

        <!-- Fonts -->
        <link rel="preconnect" href="https://fonts.bunny.net">
        <link href="https://fonts.bunny.net/css?family=figtree:400,500,600&display=swap" rel="stylesheet" />

        <!-- Scripts -->
        @vite(['resources/css/app.css', 'resources/js/app.js'])
    </head>
    <body class="font-sans text-gray-900 antialiased">
        <div class="min-h-screen flex flex-col sm:justify-center items-center pt-6 sm:pt-0 bg-gray-100 dark:bg-gray-900">
            <div>
                <a href="/">
                    
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="180" viewBox="0 0 500 180">
  <rect width="100%" height="100%" fill="rgb(243 244 246 / var(--tw-bg-opacity, 1))"/>

  <!-- Center group -->
  <g transform="translate(60,30)">
    <!-- Eye -->
    <ellipse cx="70" cy="60" rx="70" ry="40" fill="none" stroke="#0A2A66" stroke-width="8"/>
    <circle cx="70" cy="60" r="20" fill="#D72638"/>
    <circle cx="70" cy="60" r="8" fill="white"/>

    <!-- Text -->
    <text x="160" y="75" font-family="Helvetica-Bold, Arial, sans-serif" font-size="60" fill="#0A2A66">
      Vuln<tspan fill="#D72638">Eye</tspan>
    </text>
  </g>
</svg>
                </a>
            </div>

            <div class="w-full sm:max-w-md mt-6 px-6 py-4 bg-white dark:bg-gray-800 shadow-md overflow-hidden sm:rounded-lg">
                {{ $slot }}
            </div>
        </div>
    </body>
</html>
