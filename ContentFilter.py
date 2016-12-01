# Bitclamp: a cryptocurrency-based publication tool
# Copyright (C) 2016  Joe Testa <jtesta@positronsecurity.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms version 3 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# This class holds filter configuration data.  When data is extracted from a
# blockchain, the metadata is compared against this filter.  If it does not
# match, the caller will skip extraction of that file.

from PartialFile import *

class ContentFilter:

    def __init__(self, filename, description, content_type_const_list):
        self.filename = filename
        self.description = description
        self.content_type_const_list = content_type_const_list

        self.filename_begins_with_star = False
        self.filename_ends_with_star = False
        self.description_begins_with_star = False
        self.description_ends_with_star = False

        # Determine if the filename begins or ends with a wildcard ('*').  If
        # so, record where it was, and strip it out.
        if self.filename is not None:
            if self.filename.startswith('*'):
                self.filename = self.filename[1:]
                self.filename_begins_with_star = True

            if self.filename.endswith('*'):
                self.filename = self.filename[:-1]
                self.filename_ends_with_star = True

        # ... same with the description.
        if self.description is not None:
            if self.description.startswith('*'):
                self.description = self.description[1:]
                self.description_begins_with_star = True

            if self.description.endswith('*'):
                self.description = self.description[:-1]
                self.description_ends_with_star = True


    # Returns True iff the PartialFile argument matches this ContentFilter.
    def matches(self, partial_file):
        # If a content type filter is set, and this partial file's content type
        # is not in the list, then it does not match.
        if self.content_type_const_list is not None:
            if partial_file.content_type not in self.content_type_const_list:
                return False

        # Check if filename matches.
        if not ContentFilter.string_matches(partial_file.sanitized_filename, self.filename, self.filename_begins_with_star, self.filename_ends_with_star):
            return False

        # Check if description matches.
        if not ContentFilter.string_matches(partial_file.description, self.description, self.description_begins_with_star, self.description_ends_with_star):
            return False

        return True


    # Perform any wildcard matching on a string (filename or description).
    # Returns True if the candidate matches the filter.
    @staticmethod
    def string_matches(candidate, filter, filter_begins_with_star, filter_ends_with_star):

        if filter is not None:
            if (candidate is None) and (filter != ''):
                return False

            # If no wildcards exist, then the filter must exactly match the
            # candidate.
            if filter_begins_with_star is False and filter_ends_with_star is False:
                if filter != candidate:
                    return False

            # If the filter begins with a star, then the filter must match the
            # end of the candidate.
            elif filter_begins_with_star is True and filter_ends_with_star is False:
                if not candidate.endswith(filter):
                    return False

            # If the filter ends with a star, then the filter must match the
            # beginning of the candidate.
            elif filter_begins_with_star is False and filter_ends_with_star is True:
                if not candidate.startswith(filter):
                    return False

            # If the filter begins and ends with a star, then the filter must
            # exist anywhere within the candidate.
            else:
                if candidate.find(filter) == -1:
                    return False

        return True
