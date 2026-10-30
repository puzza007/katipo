/-!
# Pool defaults: the merge (`katipo_defaults:merge/2`)

```erlang
merge(Defaults, Base, Opts) ->
    Opts1 = url(Base, default_url(Defaults, Opts)),
    Rest = retry(Opts1, origin_only(Base, Opts1, maps:remove(url, Defaults))),
    headers(Rest, Opts1, maps:merge(Rest, Opts1)).

origin_only({_Prefix, _Path, BaseOrigin}, #{url := Url}, Defaults) ->
    case {origin(Url), BaseOrigin} of
        {{ok, Same}, {ok, Same}} -> Defaults;
        _ -> maps:without(?ORIGIN_ONLY, Defaults)
    end.

headers(#{headers := Default}, #{headers := Given}, Merged) ->
    case proper(Given) of
        true ->
            Names = [header_name(K) || {K, _} <- Given],
            Merged#{headers := Given ++ [H || {K, _} = H <- Default,
                                              not lists:member(header_name(K), Names)]};
```

Options are total functions to `Option`, `maps:merge/2` taking the request's
value where it has one. Headers are lists of pairs; `name` is
`header_name/1`, any function (ASCII case folding in the code). An origin
is `origin/1`'s: one of any type with equality, or `none` for a url whose
origin cannot be told (`BaseOrigin` is `base_url`'s, worked out when the
pool starts); `uri_string:normalize/2`, the default url, and the url's
resolution against `base_url` (`resolve/2`, RFC 3986's) are trusted.
`only` is `?ORIGIN_ONLY`, any set of keys. `retry/2` is left out.
-/

namespace KatipoProofs.Defaults.Merge

/-- `maps:merge(Defaults, Opts)`. -/
def opts {K V : Type} (d o : K → Option V) : K → Option V :=
  fun k => match o k with
    | some x => some x
    | none => d k

/-- `{{ok, Same}, {ok, Same}}`: two known, equal origins. -/
def sameOrigin {O : Type} [DecidableEq O] : Option O → Option O → Bool
  | some u, some b => decide (u = b)
  | _, _ => false

/-- `origin_only/3`, for a request whose url has origin `url`. -/
def scope {K V O : Type} [DecidableEq O] (only : K → Bool) (base url : Option O)
    (d : K → Option V) : K → Option V :=
  fun k => if sameOrigin url base then d k else if only k then none else d k

/-- `headers/3`'s list. -/
def headers {N A B : Type} [DecidableEq N] (name : A → N) (d g : List (A × B)) :
    List (A × B) :=
  g ++ d.filter (fun h => !(g.map (name ∘ Prod.fst)).contains (name h.1))

end KatipoProofs.Defaults.Merge
