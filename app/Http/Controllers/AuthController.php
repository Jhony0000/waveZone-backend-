<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Sanctum\PersonalAccessToken;


class AuthController extends Controller
{
    //register user
    public function signUp(Request $request)
    {
        // Validate the incoming data
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        // If validation fails, return errors
        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        // Create a new user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'profile_photo' => $request->profile_photo,
        ]);

        // Return a success response with user data
        return response()->json([
            'message' => 'User created successfully!',
            'user' => $user
        ], 201);
    }

    public function login(Request $request)
    {
        // Validate the incoming data
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:8',
        ]);

        // If validation fails, return errors
        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        // Attempt to log in the user
        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            // Authentication passed
            $user = Auth::user();

            // If you are using JWT, return the token
            // $token = $user->createToken('YourAppName')->plainTextToken;

            return response()->json([
                'message' => 'Login successful!',
                'user' => $user,
                // 'token' => $token,  // Send token to the frontend
            ], 200);
        } else {
            return response()->json([
                'message' => 'Invalid email or password.',
            ], 401);  // Unauthorized
        }
    }

    // Logout the user
    public function logout(Request $request)
    {
        Auth::logout();

        return response()->json([
            'message' => 'Logout successful!',
        ], 200);
    }

    //google register

    // Redirect the user to the Google authentication page
    public function googleRedirectPage()
    {
        return Socialite::driver('google')->redirect();
    }

    /**
     * Function to authenticate the user with Google
     * *Description: This function will authenticate the user with Google and log them in if they exist in the database. If the user does not exist, a new user will be created and logged in.
     * @param NA
     * @return void
     */
    public function googleAuthenticate(Request $request)
    {
        try {
            // Debug incoming request data
            // \Log::info('Google Auth Request Data:', $request->all());

            if (!$request->has(['email', 'name', 'picture', 'sub'])) {
                return response()->json([
                    'error' => 'Missing required fields',
                    'details' => $request->all()
                ], 400);
            }

            $existingUser = User::where('email', $request->email)->first();

            if ($existingUser) {
                Auth::login($existingUser);
                $user = $existingUser;
            } else {
                $user = User::create([
                    'name' => $request->name,
                    'email' => $request->email,
                    'google_id' => $request->sub,
                    'profile_photo' => $request->picture,
                    'password' => Hash::make(uniqid()),
                ]);

                Auth::login($user);
            }

            // Revoke all previous tokens (optional, for security)
            $user->tokens()->delete();

            // Generate new Access Token (valid for 30 mins)
            $accessToken = $user->createToken('access_token', ['*'], now()->addMinutes(30))->plainTextToken;

            // Generate new Refresh Token (valid for 7 days)
            $refreshToken = $user->createToken('refresh_token', ['*'], now()->addDays(60))->plainTextToken;

            return response()->json([
                'message' => 'Login successful!',
                'user' => $user,
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Google authentication failed',
                'details' => $e->getMessage(),
            ], 500);
        }
    }
    // public function refreshToken(Request $request)
    // {
    //     $user = Auth::user();

    //     if (!$user) {
    //         return response()->json(['error' => 'Unauthorized'], 401);
    //     }

    //     // Generate new Access Token
    //     $newAccessToken = $user->createToken('access_token', ['*'], now()->addMinutes(30))->plainTextToken;

    //     return response()->json([
    //         'access_token' => $newAccessToken,
    //     ]);
    // }
}
